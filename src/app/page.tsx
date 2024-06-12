"use client";
import { useZupass } from "@/zupass";
import { useZupassPopupMessages } from "@pcd/passport-interface";
import { PCD, SerializedPCD } from "@pcd/pcd-types";
import Link from "next/link";
import { ReadonlyURLSearchParams, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { OuterContainer, PageContainer, Title } from "../components/Zuzagora";
import { Button } from "../components/core/Button";
import { RippleLoader } from "../components/core/RippleLoader";
import { InputParams } from "../types";
import { authenticate } from "../utils/authenticate";
import { validateSSO } from "../utils/validateSSO";

export default function Home() {
  const [loading, setloading] = useState(false);
  const [inputParams, setInputParams] = useState<InputParams | null>(null);
  const { login } = useZupass();

  const [pcdStr, _pendingPCDStr, multiPCDs] = useZupassPopupMessages();
  
  const searchParams = useSearchParams();

  useEffect(() => {
    async function startValidation() {
      try {
        const params = await getParams(searchParams);
        if (searchParams) {
          const response = await validateSSO(params?.sso, params?.sig);
          // TODO: trigger alert if it's not valid
          if (response?.isValid) {
            setloading(false);
            setInputParams({ ...params, ...response });
          }
        }
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    }

    startValidation();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  useEffect(() => {
    (async () => {
      if (multiPCDs) {
        processProof(multiPCDs);
      }
    })();
  }, [multiPCDs]);

  const loginHandler = async () => {
    setloading(true);
    await login(inputParams);
  };

  const processProof = async (multiPCDs: SerializedPCD<PCD<unknown, unknown>>[]) => {
    try {
      const response = await authenticate(multiPCDs);
      console.log("🚀 ~ processProof ~ response:", response)
      const returnSSOURL = inputParams?.return_sso_url; // This is an example; use the actual return_sso_url from your payload.

      // Return
      if (response && returnSSOURL) {
        const redirectURL = `${returnSSOURL}?sso=${response?.encodedPayload}&sig=${response?.sig}`;
        window.location.href = redirectURL;
      } else {
        setloading(false);
      }
    } catch (error) {
      console.error(error);
      window.location.href = `${inputParams?.return_sso_url}`;
      setloading(false);
    }
  };

  if (loading) {
    return (
      <OuterContainer>
        <RippleLoader />
      </OuterContainer>
    );
  }

  return (
    <OuterContainer>
      <PageContainer>
        <div
          className="flex flex-col"
          style={{ flexGrow: 1, justifyContent: "center" }}
        >
          <img className="logo-image" src="agora-logo.png" alt="agora logo" />
          <Title>Welcome to Agora City!</Title>
          {/* <Subtitle>Select a resident ticket if you have one.</Subtitle> */}
          <Button onClick={loginHandler}>Sign In</Button>
        </div>
        <Link
          href="https://t.me/petrafran"
          target="_blank"
          style={{ color: "var(--bg-dark-primary)", margin: 15 }}
        >
          I'm having trouble connecting
        </Link>
      </PageContainer>
    </OuterContainer>
  );
}

const getParams = (searchParams: ReadonlyURLSearchParams | null) => {
  // Initialize the final object
  const finalObject: any = {};
  // Check for 'sso' parameter
  if (searchParams?.has("sso")) {
    const ssoString = searchParams?.get("sso");
    finalObject.sso = ssoString;
  }

  // Check for 'sig' parameter
  if (searchParams?.has("sig")) {
    const sigString = searchParams?.get("sig");
    finalObject.sig = sigString;
  }
  return finalObject;
};
