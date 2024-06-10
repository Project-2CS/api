import numpy as np
import joblib
from django.shortcuts import render
from utils.response.base_response import BaseResponse
from rest_framework import status
import os
import tensorflow as tf


# Load the model
model = tf.keras.models.load_model("/app/mlmodels/sqlinjection_model/sqli_model_v1.h5")


def preprocess_query(query):
    if not isinstance(query, str):
        return [0, 0, 0]
    # Length
    length = len(query)
    # Punctuation
    punctuation_count = sum(
        [
            1
            for ch in query
            if ch in ["!", ",", "'", ";", '"', ".", "-", "?", "[", "]", ")", "("]
        ]
    )
    query = "".join(
        [
            (
                " "
                if ch in ["!", ",", "'", ";", '"', ".", "-", "?", "[", "]", ")", "("]
                else ch
            )
            for ch in query
        ]
    )

    # Keywords
    keyword_count = sum(
        [
            1
            for word in query.lower().split()
            if word
            in [
                "select",
                "update",
                "insert",
                "create",
                "drop",
                "alter",
                "rename",
                "exec",
                "order",
                "group",
                "sleep",
                "count",
                "where",
            ]
        ]
    )
    return [length, punctuation_count, keyword_count]


# def predict(request):
#     if request.method == "POST":
#         query = request.POST.get("query")
#         if query:
#             features = preprocess_query(query)
#             features = np.array(features).reshape(1, 3)
#             prediction = model.predict(features)
#             prediction_label = "sqli" if prediction[0] >= 5.9 else "non-sqli"
#             return BaseResponse(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 error=True,
#                 message=prediction_label,
#                 data="sql injection detected",
#             )

#         return BaseResponse(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             error=True,
#             message="No query provided",
#             data="",
#         )


def predict_single_query(query):
    features = preprocess_query(query)
    features = np.array(features).reshape(1, 1, 3)
    prediction = model.predict(features)
    prediction_label = "sqli" if prediction[0] >= 4.5 else "non-sqli"
    return {
        "query": query,
        "prediction": prediction[0],
        "label": prediction_label,
        "sql_injection": True if prediction_label == "sqli" else False,
    }


# def predict(self, request):
#     print(request.data)
#     predictions = {}
#     for field, query in request.data.items():

#         if query:
#             prediction = predict_single_query(query)
#             predictions[field] = prediction
#             # print("**********")
#             # print(field)
#             # print(query)
#             # print(prediction)
#             # print("**********")
#         else:
#             predictions[field] = {"error": "No query provided for this field"}

#     print(predictions)
#     for field, value in predictions.items():
#         if value["sql_injection"] == True:
#             print("****************************************")
#             print("SQL injection detected")
#             print("----------------------------------------")
#             print(predictions)
#             print("****************************************")
#             return {"sql_injection": True, "message": "SQL injection detected"}

#     return {"sql_injection": False, "message": "Everthing seem fine"}
def predict(self, request):
    # print(request.data)
    sqli_queries = []
    predictions = {}
    for field, query in request.data.items():

        if query:
            prediction = predict_single_query(query)
            predictions[field] = prediction

            if prediction["sql_injection"] == True:
                sqli_queries.append(query)

            # print("********")
            # print(field)
            # print(query)
            # print(prediction)
            # print("********")
        else:
            predictions[field] = {"error": "No query provided for this field"}

    # print(sqli_queries)
    for field, value in predictions.items():
        if value["sql_injection"] == True:
            # print("**************************************")
            # print("SQL injection detected")
            # print("----------------------------------------")
            # print(predictions)
            # print("**************************************")
            return {
                "sql_injection": True,
                "message": "SQL injection detected",
                "sqli_queries": sqli_queries,
            }

    return {
        "sql_injection": False,
        "message": "Everthing seem fine",
        "sqli_queries": None,
    }