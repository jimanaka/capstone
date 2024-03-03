import axios from "axios";
import cookies from "js-cookie";
const API_URL = "http://localhost:80/api/";

export const insertCourseService = async ({ course }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "insert-course",
      { course },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: Unable to insert course");
    throw error;
  }
};
