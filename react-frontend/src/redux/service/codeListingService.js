import axios from "axios";
import cookies from "js-cookie";
const API_URL = "http://localhost:80/revenv/";

export const getFileInfoService = async ({ filename }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "get-file-info",
      { filename },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: unable to get file info");
    throw error;
  }
};

export const disassembleBinaryService = async ({ filename }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "disassemble-binary",
      { filename },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: unable to disassemble file");
    throw error;
  }
};

export const decompileFunctionService = async ({ filename, address }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "decompile-function",
      { filename, address },
      config,
    );
    return response;
  } catch (error) {
    console.error(`error: unable to decompile function for file ${filename} at ${address}`);
    throw error;
  }
};
