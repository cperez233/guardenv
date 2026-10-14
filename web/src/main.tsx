/* editorial-ui · Cristian Pérez · cristianperez.me */
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import "./index.css";

const container = document.getElementById("root");
if (container === null) {
  throw new Error("GuardEnv: #root is missing from index.html");
}

console.info(
  "%cGuardEnv%c · built with care by Cristian Pérez · https://cristianperez.me",
  "font-weight:700;background:#e3f24a;color:#101317;padding:1px 4px",
  "",
);

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
