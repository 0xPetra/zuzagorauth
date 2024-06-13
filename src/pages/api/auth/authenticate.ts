import { generateSignature } from "@/utils/generateSignature";
import { supportedEvents, whitelistedTickets } from "@/zupass-config";
import { isEqualEdDSAPublicKey } from "@pcd/eddsa-pcd";
import { ZKEdDSAEventTicketPCDPackage } from "@pcd/zk-eddsa-event-ticket-pcd";
import { withIronSessionApiRoute } from "iron-session/next";
import { NextApiRequest, NextApiResponse } from "next";

const nullifiers = new Set<string>();

declare module "iron-session" {
  interface IronSessionData {
    nonce?: string;
    user?: string;
  }
}

const authRoute = async (req: NextApiRequest, res: NextApiResponse) => {
  try {
    const { body: pcds } = req;

    if (!Array.isArray(pcds) || pcds.length === 0) {
      return res
        .status(400)
        .json({ message: "No PCDs specified or invalid input format." });
    }

    const responses = [];

    for (const { type, pcd: inputPCD } of pcds) {
      if (type !== "zk-eddsa-event-ticket-pcd") {
        responses.push({ error: `Invalid PCD type: ${type}`, status: 400 });
        continue;
      }

      const pcd = await ZKEdDSAEventTicketPCDPackage.deserialize(inputPCD);
      const nonce = req.session?.nonce;

      if (!inputPCD || !pcd) {
        responses.push({
          error: "Invalid PCD format or deserialization error",
          status: 400
        });
        continue;
      }

      if (!(await ZKEdDSAEventTicketPCDPackage.verify(pcd))) {
        responses.push({ error: "ZK ticket PCD is not valid", status: 401 });
        continue;
      }

      if (!nonce) {
        responses.push({ error: "No nonce in session", status: 401 });
        continue;
      }

      const bigIntNonce = BigInt("0x" + nonce);

      if (pcd.claim.watermark.toString() !== bigIntNonce.toString()) {
        responses.push({ error: "PCD watermark doesn't match", status: 401 });
        continue;
      }

      if (!pcd.claim.nullifierHash) {
        responses.push({
          error: "PCD ticket nullifier has not been defined",
          status: 401
        });
        continue;
      }

      if (nullifiers.has(pcd.claim.nullifierHash)) {
        responses.push({
          error: "PCD ticket has already been used",
          status: 401
        });
        continue;
      }

      if (pcd.claim.partialTicket.eventId) {
        const eventId = pcd.claim.partialTicket.eventId;
        if (!supportedEvents.includes(eventId)) {
          responses.push({
            error: `PCD ticket is not for a supported event: ${eventId}`,
            status: 400
          });
          continue;
        }
      } else {
        for (const eventId of pcd.claim.validEventIds ?? []) {
          if (!supportedEvents.includes(eventId)) {
            responses.push({
              error: `PCD ticket is not restricted to supported events: ${eventId}`,
              status: 400
            });
            break;
          }
        }
      }

      nullifiers.add(pcd.claim.nullifierHash);
      req.session.user = pcd.claim.nullifierHash;
      await req.session.save();

      const { encodedPayload, signature, ticketType } = await generateSignature(
        pcd,
        nonce
      );
      if (!encodedPayload || !signature) {
        responses.push({
          error: "Signature couldn't be generated",
          status: 500
        });
        continue;
      }

      if (ticketType === undefined) continue;

      const tickets = whitelistedTickets[ticketType];
      const publicKey = tickets[0].publicKey;

      if (!isEqualEdDSAPublicKey(publicKey, pcd.claim.signer)) {
        responses.push({ error: "PCD is not signed by Zupass", status: 401 });
        continue;
      }

      responses.push({
        attendeeEmail: pcd.claim.partialTicket.attendeeEmail,
        encodedPayload,
        sig: signature,
        status: 200
      });
    }

    res.status(200).json(responses);
  } catch (error: any) {
    console.error(`[ERROR] ${error.message}`);
    res.status(500).json(`Unknown error: ${error.message}`);
  }
};

const ironOptions = {
  cookieName: process.env.SESSION_COOKIE_NAME as string,
  password: process.env.SESSION_PASSWORD as string,
  cookieOptions: {
    secure: process.env.NODE_ENV === "production"
  }
};

export default withIronSessionApiRoute(authRoute, ironOptions);
