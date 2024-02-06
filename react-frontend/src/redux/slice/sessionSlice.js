import { createSlice } from "@reduxjs/toolkit";

const sessionSlice = createSlice({
  name: "session",
  initialState: {
    isConnected: false,
    gdbPID: null,
    gdbState: null,
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
  },
});

export const {
  initSocket,
  disconnect,
  connectionEstablished,
  connectionLost,
  setGdbPID,
  sendCommand,
} = sessionSlice.actions;
export default sessionSlice.reducer;
