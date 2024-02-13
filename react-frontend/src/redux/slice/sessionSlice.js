import { createSlice } from "@reduxjs/toolkit";

const sessionSlice = createSlice({
  name: "session",
  initialState: {
    isConnected: false,
    gdbPID: null,
    gdbState: null,
    gdbStoppedReason: null,
    programOutput: null,
    disassemblyOutput: null,
    gdbFrame: null,
    gdbBreakpoints: [],
    gdbRegisterNames: [],
    gdbRegisterValues: [],
    gdbChangedRegisters: [],
    gdbStack: [],
  },
  reducers: {
    initSocket: () => {
      return;
    },
    disconnect: () => {
      return;
    },
    sendCommand: () => {
      return;
    },
    connectionEstablished: (state) => {
      state.isConnected = true;
    },
    connectionLost: (state) => {
      state.isConnected = false;
    },
    setGdbPID: (state, action) => {
      state.gdbPID = action.payload;
    },
    setProgramOutput: (state, action) => {
      state.programOutput = action.payload;
    },
    setGdbState: (state, action) => {
      state.gdbState = action.payload;
    },
    setGdbStoppedReason: (state, action) => {
      state.gdbStoppedReason = action.payload;
    },
    setDisassemblyOutput: (state, action) => {
      state.disassemblyOutput = action.payload;
    },
    setGdbFrame: (state, action) => {
      state.gdbFrame = action.payload;
    },
    addGdbBreakpoint: (state, action) => {
      state.gdbBreakpoints.push(action.payload);
    },
    setGdbBreakpoints: (state, action) => {
      state.gdbBreakpoints = action.payload;
    },
    setGdbRegisterNames: (state, action) => {
      state.gdbRegisterNames = action.payload;
    },
    setGdbRegisterValues: (state, action) => {
      state.gdbRegisterValues = action.payload;
    },
    setGdbChangedRegisters: (state, action) => {
      state.gdbChangedRegisters = action.payload;
    },
    setGdbStack: (state, action) => {
      state.gdbStack = action.payload;
    }
  },
});

export const {
  initSocket,
  disconnect,
  connectionEstablished,
  connectionLost,
  setGdbPID,
  sendCommand,
  setProgramOutput,
  setGdbState,
  setGdbStoppedReason,
  setDisassemblyOutput,
  setGdbFrame,
  addGdbBreakpoint,
  setGdbBreakpoints,
  setGdbRegisterNames,
  setGdbRegisterValues,
  setGdbChangedRegisters,
  setGdbStack,
} = sessionSlice.actions;
export default sessionSlice.reducer;
