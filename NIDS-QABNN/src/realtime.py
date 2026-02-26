def simulate_stream(model, X_stream):
    results = []
    for sample in X_stream:
        pred = model.predict(sample.reshape(1, -1))
        results.append(pred[0])
    return results
