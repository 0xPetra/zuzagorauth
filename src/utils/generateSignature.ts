import { PCD } from "@pcd/pcd-types";
import { ZKEdDSAEventTicketPCDClaim } from "@pcd/zk-eddsa-event-ticket-pcd";
import { Groth16Proof } from "@zk-kit/groth16";
import crypto from "crypto";
import { matchTicketToType } from "../zupass-config";
import { toUrlEncodedString } from "./toUrl";

export const generateSignature = async (
  pcds: PCD<ZKEdDSAEventTicketPCDClaim, Groth16Proof>[],
  nonce: string
) => {
  try {
    // console.log("🚀 ~ generateSignature ~ pcds:", pcds);

    const groups: string[] = [];

    // Extract the desired fields and collect ticket types
    for (const pcd of pcds) {
      const eventId = pcd.claim.partialTicket.eventId;
      const productId = pcd.claim.partialTicket.productId;

      if (!eventId || !productId) {
        throw new Error("No product or event selected.");
      }

      console.log("🚀 ~ eventId, productId:", eventId, productId)
      const ticketType = matchTicketToType(eventId, productId);
      console.log("🚀 ~ ticketType:", ticketType)
      if (!ticketType) {
        throw new Error("Unable to determine ticket type.");
      }
      groups.push(ticketType);
    }

    const payload = {
      nonce: nonce,
      email: pcds.map((pcd) => pcd.claim.partialTicket.attendeeEmail).join(","), // Concatenate emails
      external_id: pcds
        .map((pcd) => pcd.claim.partialTicket.attendeeSemaphoreId)
        .join(","), // Concatenate semaphore IDs
      add_groups: groups.join(",") // Join ticket types with comma separator
    };

    // Encoding payload to Base64
    const urlPayload = toUrlEncodedString(payload);
    const encodedPayload = Buffer.from(urlPayload).toString("base64");

    const secret = process.env.DISCOURSE_CONNECT_SECRET;

    if (typeof secret !== "string") {
      throw new Error(
        "You need to set DISCOURSE_CONNECT_SECRET as an environment variable."
      );
    }

    // Compute the HMAC-SHA256
    const signature = crypto
      .createHmac("sha256", secret)
      .update(encodedPayload)
      .digest("hex");

    console.log("Encoded Payload:", encodedPayload);
    console.log("Signature:", signature);
    console.log("groups", groups);
    return { encodedPayload, signature, ticketType: groups };
  } catch (error) {
    console.error("There was an error generating the signature:", error);
    throw new Error("There was an error generating the signature.");
  }
};
