import {
  setGdbState,
  setGdbStoppedReason,
  sendCommand,
  setDisassemblyOutput,
  setGdbFrame,
} from "../redux/slice/sessionSlice";

export const handleGdbGuiResponse = (store, socket, msg) => {
  if (msg.type === "notify") {
    switch (msg.message) {
      case "running":
        store.dispatch(setGdbState(msg.message));
        break;
      case "stopped":
        store.dispatch(setGdbState(msg.message));
        store.dispatch(setGdbStoppedReason(msg.payload.reason));
        store.dispatch(setGdbFrame(msg.payload.frame));
        store.dispatch(sendCommand(`-data-disassemble -a ${msg.payload.frame.func}`))
        // if (msg.payload.reason === "breakpoint-hit") {
        //   // store.dispatch(sendCommand('-data-disassemble -a "$pc" -- 0'));
        // }
        break;
    }
  } else if (msg.type === "result") {
    if (msg.payload.hasOwnProperty("asm_insns")) {
      store.dispatch(setDisassemblyOutput(msg.payload.asm_insns))
    } else if (msg.payload.hasOwnProperty("bkpt")) {
      console.log(msg.payload.bkpt);
    }
  }
};
