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
    console.log(formData);
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
