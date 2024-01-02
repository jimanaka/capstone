import axios from "axios";
import { API_URL } from "./authService";


export const login = ({ username, password }) => {
  try {
    const config = {
      headers: {
        "Content-Type": "application/json",
      },
    };
    const response = await axios.post(
      API_URL + "login",
      { username, password },
      config
    );
    return response.data;
  } catch (error) {
    if (error.response && error.response.data.message) {
      return rejectWithValue(error.response.data.message);
    }
    return rejectWithValue(error.message);
  }
};
