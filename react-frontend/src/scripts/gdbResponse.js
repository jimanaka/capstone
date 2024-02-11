import {
  setGdbState,
  setGdbStoppedReason,
  sendCommand,
  setDisassemblyOutput,
  setGdbFrame,
  addGdbBreakpoint,
  setGdbRegisterValues,
  setGdbRegisterNames,
  setGdbChangedRegisters,
} from "../redux/slice/sessionSlice";

export const handleGdbGuiResponse = (store, socket, msg) => {
  switch (msg.type) {
    case "notify":
      if (msg.message === "running") store.dispatch(setGdbState(msg.message));
      else if (msg.message === "stopped") {
        store.dispatch(setGdbState(msg.message));
        store.dispatch(setGdbStoppedReason(msg.payload.reason));
        store.dispatch(setGdbFrame(msg.payload.frame));
        // register values can go up to 0-17, but I am leaving out 8-15 as they are general purpose registers
        store.dispatch(
          sendCommand(
            `-data-disassemble -a ${msg.payload.frame.func} \n` +
              `-data-list-register-names 0 1 2 3 4 5 6 7 16 17 \n` +
              `-data-list-register-values x 0 1 2 3 4 5 6 7 16 17 \n` +
              `-data-list-changed-registers`,
          ),
        );
      }
      break;
    case "result":
      if (msg.payload.hasOwnProperty("asm_insns")) {
        store.dispatch(setDisassemblyOutput(msg.payload.asm_insns));
      } else if (msg.payload.hasOwnProperty("bkpt")) {
        store.dispatch(addGdbBreakpoint(msg.payload.bkpt));
      } else if (msg.payload.hasOwnProperty("register-names")) {
        store.dispatch(setGdbRegisterNames(msg.payload["register-names"]));
      } else if (msg.payload.hasOwnProperty("register-values")) {
        store.dispatch(setGdbRegisterValues(msg.payload["register-values"]));
      } else if (msg.payload.hasOwnProperty("changed-registers")) {
        store.dispatch(
          setGdbChangedRegisters(
            msg.payload["changed-registers"].length > 18
              ? msg.payload["changed-registers"].slice(0, 18)
              : msg.payload["changed-registers"],
          ),
        );
      }
      break;
  }
};
