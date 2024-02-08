import { setGdbState, setGdbStoppedReason, sendCommand } from "../redux/slice/sessionSlice";

export const handleGdbGuiResponse = (store, socket, msg) => {
  if (msg.type === "notify") {
    switch (msg.message) {
      case "running":
        store.dispatch(setGdbState(msg.message));
        break;
      case "stopped":
        store.dispatch(setGdbState(msg.message));
        store.dispatch(setGdbStoppedReason(msg.payload.reason));
        if (msg.payload.reason === "breakpoint-hit") {
          store.dispatch(sendCommand('-data-disassemble -a "$pc" -- 0'))
        }
        break;
    }
  } 

  else if (msg.type === "result") {
    console.log(msg);
    if (msg.payload.hasOwnProperty("asm_insns")) {
      console.log(msg.payload.asm_insns);
    }
    else if (msg.payload.hasOwnProperty("bkpt")) {
      console.log(msg.payload.bkpt);
    }
  }
}
