import pandas as pd
import re
from urllib.parse import urlparse
from datetime import datetime

df = pd.read_csv('Input_alert_data/SentinelHighSeverityIncidentsDataperweek.csv')
entities = (df[['Entities']])
print(entities.head())
# print(entities.to_string())