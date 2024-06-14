import { generateSignature } from "@/utils/generateSignature";
import { supportedEvents, whitelistedTickets } from "@/zupass-config";
import { isEqualEdDSAPublicKey } from "@pcd/eddsa-pcd";
import {
  ZKEdDSAEventTicketPCD,
  ZKEdDSAEventTicketPCDPackage
} from "@pcd/zk-eddsa-event-ticket-pcd";
import { withIronSessionApiRoute } from "iron-session/next";
import { NextApiRequest, NextApiResponse } from "next";

const nullifiers = new Set<string>();

declare module "iron-session" {
  interface IronSessionData {
    nonce?: string;
    user?: string;
  }
}

type TicketType = keyof typeof whitelistedTickets;

const authRoute = async (req: NextApiRequest, res: NextApiResponse) => {
  try {
    const { body: pcds } = req;

    if (!Array.isArray(pcds) || pcds.length === 0) {
      return res
        .status(400)
        .json({ message: "No PCDs specified or invalid input format." });
    }

    console.log("Received PCDs:", pcds); // Log received PCDs

    const validPcds: ZKEdDSAEventTicketPCD[] = [];
    const responses: { error: string; status: number }[] = [];
    const nonce = req.session?.nonce;

    if (!nonce) {
      return res.status(401).json({ message: "No nonce in session" });
    }

    const bigIntNonce = BigInt("0x" + nonce);

    for (const { type, pcd: inputPCD } of pcds) {
      console.log("Processing PCD:", inputPCD); // Log input PCD

      if (type !== "zk-eddsa-event-ticket-pcd") {
        responses.push({ error: `Invalid PCD type: ${type}`, status: 400 });
        continue;
      }

      const pcd = await ZKEdDSAEventTicketPCDPackage.deserialize(inputPCD);
      console.log("Deserialized PCD:", pcd); // Log deserialized PCD

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
        let eventError = false;
        for (const eventId of pcd.claim.validEventIds ?? []) {
          if (!supportedEvents.includes(eventId)) {
            responses.push({
              error: `PCD ticket is not restricted to supported events: ${eventId}`,
              status: 400
            });
            eventError = true;
            break;
          }
        }
        if (eventError) continue;
      }

      // Check for duplicate PCDs
      const existingPcd = validPcds.find(
        (validPcd) => validPcd.claim.nullifierHash === pcd.claim.nullifierHash
      );
      if (!existingPcd) {
        nullifiers.add(pcd.claim.nullifierHash);
        req.session.user = pcd.claim.nullifierHash;
        await req.session.save();

        validPcds.push(pcd);
      } else {
        console.log("Duplicate PCD found and skipped:", pcd); // Log duplicate PCD
      }
    }

    console.log("Valid PCDs after processing:", validPcds); // Log valid PCDs

    if (validPcds.length > 0) {
      console.log("Valid PCDs for generateSignature:", validPcds);

      const { encodedPayload, signature, ticketType } = await generateSignature(
        validPcds,
        nonce
      );

      if (!encodedPayload || !signature) {
        return res
          .status(500)
          .json({ message: "Signature couldn't be generated" });
      }

      const tickets = whitelistedTickets[ticketType as unknown as TicketType];
      const publicKey = tickets[0].publicKey;

      for (const pcd of validPcds) {
        if (!isEqualEdDSAPublicKey(publicKey, pcd.claim.signer)) {
          responses.push({ error: "PCD is not signed by Zupass", status: 401 });
          continue;
        }
      }

      const finalResponse = {
        attendeeEmail: validPcds[0].claim.partialTicket.attendeeEmail,
        encodedPayload,
        sig: signature,
        status: 200
      };

      res.status(200).json(finalResponse);
    } else {
      res.status(400).json({ message: "No valid PCDs found" });
    }
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
