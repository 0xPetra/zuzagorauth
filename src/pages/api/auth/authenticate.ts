// pages/api/auth/authenticate.ts
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
      const { pcds: inputPCDs } = req.body;
      const pcd = await ZKEdDSAEventTicketPCDPackage.deserialize(req.body.pcd);
      const nonce = req.session?.nonce

      if (req.method !== 'POST') {
         res.status(405).json({ message: 'Method Not Allowed' });
         return
      }

      if (!inputPCDs) {
         res.status(400).json({ message: 'No PCD specified.' });
         return
      }

      if (!(await ZKEdDSAEventTicketPCDPackage.verify(pcd))) {
        console.error(`[ERROR] ZK ticket PCD is not valid`);
        res.status(401).send("ZK ticket PCD is not valid");
        return;
      }
      
      if (!nonce) {
        console.error(`[ERROR]  No nonce in session`);
        res.status(401).send(" No nonce in session");
        return;
      }

      // CHECK WATERMARK IS SAME AS NONCE SAVED IN /validate-sso
      const bigIntNonce = BigInt('0x' + nonce);
      
      if (pcd.claim.watermark.toString() !== bigIntNonce.toString()) {
        console.error(`[ERROR] PCD watermark doesn't match`);
        res.status(401).send("PCD watermark doesn't match");
        return;
      }

      if (!pcd.claim.nullifierHash) {
        console.error(`[ERROR] PCD ticket nullifier has not been defined`);
        res.status(401).send("PCD ticket nullifer has not been defined");
        return;
      }

      if (nullifiers.has(pcd.claim.nullifierHash)) {
        console.error(`[ERROR] PCD ticket has already been used`);
        res.status(401).send("PCD ticket has already been used");
        return;
      }

      if (pcd.claim.partialTicket.eventId) {
        const eventId = pcd.claim.partialTicket.eventId;
        if (!supportedEvents.includes(eventId)) {
          console.error(
            `[ERROR] PCD ticket has an unsupported event ID: ${eventId}`
          );
          res.status(400).send("PCD ticket is not for a supported event");
          return;
        }
      } else {
        for (const eventId of pcd.claim.validEventIds ?? []) {
          if (!supportedEvents.includes(eventId)) {
            console.error(
              `[ERROR] PCD ticket might have an unsupported event ID: ${eventId}`
            );
            res
              .status(400)
              .send("PCD ticket is not restricted to supported events");
            return;
          }
        }
      }

      // The PCD's nullifier is saved so that it prevents the
      // same PCD from being reused for another login.
      nullifiers.add(pcd.claim.nullifierHash);

      // The user value is anonymous as the nullifier
      // is the hash of the user's Semaphore identity and the
      // external nullifier (i.e. nonce).
      req.session.user = pcd.claim.nullifierHash;
      await req.session.save();

      const { encodedPayload, signature, ticketType } = await generateSignature(pcd, nonce)
      if (!encodedPayload || !signature) {
        res.status(500).json("Signature couldn't be generated");
        return
      }

      if (ticketType === undefined) return;

      const tickets = whitelistedTickets[ticketType];
      // All event's within the same Ticket Type share the same public keys, so we select the first one.
      const publicKey = tickets[0].publicKey; 
      
      if (!isEqualEdDSAPublicKey(publicKey, pcd.claim.signer)) {
        console.error(`[ERROR] PCD is not signed by Zupass`);
        res.status(401).send("PCD is not signed by Zupass");
        return;
      }

      res.send({
        attendeeEmail: pcd.claim.partialTicket.attendeeEmail,
        encodedPayload,
        sig: signature
      })
      return;
    } catch (error: any) {
      console.error(`[ERROR] ${error.message}`);
      res.status(500).json(`Unknown error: ${error.message}`);
      return;
    }
};

const ironOptions = {
  cookieName: process.env.SESSION_COOKIE_NAME as string,
  password: process.env.SESSION_PASSWORD as string,
  cookieOptions: {
    secure: process.env.NODE_ENV === "production"
  }
}

export default withIronSessionApiRoute(authRoute, ironOptions);