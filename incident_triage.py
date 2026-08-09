import pandas as pd
from datetime import datetime

df = pd.read_csv('Input_alert_data/SentinelHighSeverityIncidentsDataperweek.csv')
print(df.head())