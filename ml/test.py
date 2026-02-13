from predict import predict

sample = {
    "method": "GET",
    "url": "/search",
    "query": "id=1 OR 1=1",
    "body": ""
}

print(predict(sample))
