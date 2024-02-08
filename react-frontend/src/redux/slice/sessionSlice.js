import { createSlice } from "@reduxjs/toolkit";

const sessionSlice = createSlice({
  name: "session",
  initialState: {
    isConnected: false,
    gdbPID: null,
    gdbState: null,
    gdbStoppedReason: null,
    programOutput: null,
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
} = sessionSlice.actions;
export default sessionSlice.reducer;
