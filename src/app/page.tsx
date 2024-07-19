"use client";
import { useZupass } from "@/zupass";
import { useZupassPopupMessages } from "@pcd/passport-interface";
import { SerializedPCD } from "@pcd/pcd-types";
import Link from "next/link";
import { ReadonlyURLSearchParams, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { OuterContainer, PageContainer } from "../components/Zuzagora";
import { Button } from "../components/core/Button";
import { RippleLoader } from "../components/core/RippleLoader";
import { InputParams } from "../types";
import { authenticate } from "../utils/authenticate";
import { validateSSO } from "../utils/validateSSO";

export default function Home() {
  const [loading, setLoading] = useState(false);
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
          if (response?.isValid) {
            setLoading(false);
            setInputParams({ ...params, ...response });
          }
        }
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    }

    startValidation();
  }, [searchParams]);

  useEffect(() => {
    if (multiPCDs) {
      processProof(multiPCDs);
    }
  }, [multiPCDs]);

  const loginHandler = async () => {
    setLoading(true);
    await login(inputParams);
  };

  const processProof = async (multiPCDs: SerializedPCD[]) => {
    try {
      const response = await authenticate(multiPCDs);
      // console.log("🚀 ~ processProof ~ response:", response);
      console.log(response.encodedPayload);
      const returnSSOURL = inputParams?.return_sso_url;

      if (response && returnSSOURL) {
        const redirectURL = `${returnSSOURL}?sso=${response?.encodedPayload}&sig=${response?.sig}`;
        window.location.href = redirectURL;
      } else {
        setLoading(false);
      }
    } catch (error) {
      console.error(error);
      setLoading(false);
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
          className="flex-col"
          style={{ justifyContent: "center" }}
        >
          <img className="logo-image" src="logoicon.png" alt="agora logo" />
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
  const finalObject: any = {};

  if (searchParams?.has("sso")) {
    finalObject.sso = searchParams.get("sso");
  }

  if (searchParams?.has("sig")) {
    finalObject.sig = searchParams.get("sig");
  }

  return finalObject;
};
