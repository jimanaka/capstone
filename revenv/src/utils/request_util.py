def corsify_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

