// Import necessary modules and types
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

    // Validate input format
    if (!Array.isArray(pcds) || pcds.length === 0) {
      return res
        .status(400)
        .json({ message: "No PCDs specified or invalid input format." });
    }

    const validPcds = [];
    const responses = [];
    const nonce = req.session?.nonce;

    if (!nonce) {
      return res.status(401).json({ message: "No nonce in session" });
    }

    const bigIntNonce = BigInt("0x" + nonce);

    // Process each PCD in the request
    for (const { type, pcd: inputPCD } of pcds) {
      if (type !== "zk-eddsa-event-ticket-pcd") {
        responses.push({ error: `Invalid PCD type: ${type}`, status: 400 });
        continue;
      }

      const pcd = await ZKEdDSAEventTicketPCDPackage.deserialize(inputPCD);

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

      // // Check if the PCD has already been used
      // if (nullifiers.has(pcd.claim.nullifierHash)) {
      //   responses.push({
      //     error: "PCD ticket has already been used",
      //     status: 401
      //   });
      //   continue;
      // }

      // Validate the event ID
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
        // Validate against valid event IDs
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

      // Add the nullifier hash to the set
      nullifiers.add(pcd.claim.nullifierHash);
      req.session.user = pcd.claim.nullifierHash;
      await req.session.save();

      // Push valid PCDs to the array
      validPcds.push(pcd);
    }

    // Generate signature if there are valid PCDs
    if (validPcds.length > 0) {
      const { encodedPayload, signature, ticketType } = await generateSignature(
        validPcds,
        nonce
      );

      if (!encodedPayload || !signature) {
        return res
          .status(500)
          .json({ message: "Signature couldn't be generated" });
      }

      // Get the public key from whitelisted tickets
      const tickets = whitelistedTickets[ticketType];
      const publicKey = tickets[0].publicKey;

      // Verify each PCD against the public key (optional, depending on your logic)
      for (const pcd of validPcds) {
        if (!isEqualEdDSAPublicKey(publicKey, pcd.claim.signer)) {
          responses.push({ error: "PCD is not signed by Zupass", status: 401 });
          continue;
        }
      }

      // Construct the final response object
      const finalResponse = {
        attendeeEmail: validPcds[0].claim.partialTicket.attendeeEmail, // Assuming all PCDs have the same attendee email
        encodedPayload,
        sig: signature,
        status: 200
      };

      // Send the final response
      res.status(200).json(finalResponse);
    } else {
      // If no valid PCDs were found
      res.status(400).json({ message: "No valid PCDs found" });
    }
  } catch (error: any) {
    console.error(`[ERROR] ${error.message}`);
    res.status(500).json(`Unknown error: ${error.message}`);
  }
};

// Iron session options
const ironOptions = {
  cookieName: process.env.SESSION_COOKIE_NAME as string,
  password: process.env.SESSION_PASSWORD as string,
  cookieOptions: {
    secure: process.env.NODE_ENV === "production"
  }
};

// Export withIronSessionApiRoute with authRoute and ironOptions
export default withIronSessionApiRoute(authRoute, ironOptions);
