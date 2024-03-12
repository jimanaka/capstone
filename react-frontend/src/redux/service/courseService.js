import axios from "axios";
import cookies from "js-cookie";
const API_URL = "http://localhost:80/api/";

export const addCorrectAnswerService = async ({ courseId, questionNum }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "add-correct-answer",
      { courseId, questionNum },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: Unable to get course");
    throw error;
  }
};

export const getCompleteQuestionsService = async ({ courseId }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "get-complete-questions",
      { courseId },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: Unable to get registered course or complete questions list");
    throw error;
  }
};

export const getRegisteredCourseService = async ({ courseId }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "get-registered-course",
      { courseId },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: Unable to get course");
    throw error;
  }
};

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

export const getAvailableCoursesService = async () => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.get(API_URL + "get-available-courses", config);
    return response;
  } catch (error) {
    console.error("error: Unable to get courses");
    throw error;
  }
};

export const getRegisteredCoursesService = async () => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.get(
      API_URL + "get-registered-courses",
      config,
    );
    return response;
  } catch (error) {
    console.error("error: Unable to get courses");
    throw error;
  }
};

export const registerCourseService = async ({ courseId }) => {
  try {
    const config = {
      headers: {
        "X-CSRF-TOKEN": cookies.get("csrf_access_token"),
        "Content-Type": "application/json",
      },
      withCredentials: true,
    };
    const response = await axios.post(
      API_URL + "register-course",
      { courseId },
      config,
    );
    return response;
  } catch (error) {
    console.error("error: Unable to register course");
    throw error;
  }
};
