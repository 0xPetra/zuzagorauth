import { PCD, SerializedPCD } from "@pcd/pcd-types";

export const authenticate = async (
  multiPCDs: SerializedPCD<PCD<unknown, unknown>>[]
) => {
  try {
    const response = await fetch(`/api/auth/authenticate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(multiPCDs)
    });
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("There was an error with the validation:", error);
    return false;
  }
};
