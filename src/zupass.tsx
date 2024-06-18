import { ZuAuthArgs, zuAuthPopup } from "@pcd/zuauth";
import { InputParams, TicketTypeName } from "./types";
import { whitelistedTickets } from "./zupass-config";

async function login(inputParams: InputParams | null) {
  if (inputParams === null) return;

  const bigIntNonce = BigInt("0x" + inputParams.nonce.toString());
  const watermark = bigIntNonce.toString();

  // Ensure the tickets are formatted correctly
  const config = Object.entries(whitelistedTickets).flatMap(
    ([ticketType, tickets]) =>
      tickets
        .map((ticket) => {
          if (ticket.eventId && ticket.productId) {
            return {
              pcdType: ticket.pcdType,
              ticketType: ticketType as TicketTypeName,
              eventId: ticket.eventId,
              productId: ticket.productId,
              eventName: ticket.eventName || "",
              productName: ticket.productName || "",
              publicKey: ticket.publicKey
            };
          }
          console.error("Invalid ticket format:", ticket);
          return null;
        })
        .filter(
          (ticket): ticket is NonNullable<typeof ticket> => ticket !== null
        )
  );

  const args: ZuAuthArgs = {
    fieldsToReveal: {
      revealAttendeeEmail: true,
      revealAttendeeName: true,
      revealEventId: true,
      revealProductId: true,
      revealAttendeeSemaphoreId: true
    },
    // zupassUrl: ZUPASS_URL,
    returnUrl: window.location.origin,
    watermark,
    config,
    proofTitle: "Sign-In with Zupass",
    proofDescription: "**Use Zupass to login to Agora City**",
    multi: true
  };

  const result = await zuAuthPopup(args);
  console.log("🚀 ~ login ~ result:", result);
}

export function useZupass(): {
  login: (params: InputParams | null) => Promise<void>;
} {
  return { login };
}
