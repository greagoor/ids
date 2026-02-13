import pandas as pd

df = pd.read_csv("dataset.csv", header=None)
print(df.sum())
