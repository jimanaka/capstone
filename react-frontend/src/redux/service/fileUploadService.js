import axios from "axios";
import cookies from "js-cookie";
const API_URL = "http://localhost:80/revenv/";

export const uploadFileService = async ({ file }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "multipart/form-data",
      },
      withCredentials: true,
    };
    let formData = new FormData();
    formData.append("file", file)
    const response = await axios.post(
      API_URL + "upload-file",
      formData,
      config,
    );
    return response;
  } catch (error) {
    console.error("error: Unable to upload file");
    throw error;
  }
};

export const listFilesService = async () => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.get(
      API_URL + "list-files",
      config,
    );
    return response;
  } catch (error) {
    console.error("error: Unable to get file list");
    throw error;
  }
}

export const deleteFileService = async ({ filename }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "delete-file",
      { filename },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: Unable to delete file");
    throw error;
  }
}
