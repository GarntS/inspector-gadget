#!/usr/bin/env python3
# file:     graph_core_runtimes.py
# author:   garnt
# date:     04/16/2024
# desc:     matplotlib grapher for runtimes data.

from matplotlib import pyplot as plt
import pandas as pd

# read tsv file as pandas dataframe
df = pd.read_csv('tests.csv')
df['elapsed'] = pd.to_timedelta(df.elapsed)
df['elapsed'] = df['elapsed'].dt.total_seconds()

# do mean
df_avgs = df.groupby('cores')['elapsed'].mean().reset_index()
print(df_avgs)

# add column for elapsed time-per-core
df['cpu_time'] = df['elapsed'] * df['cores']
df_avgs['cpu_time'] = df_avgs['elapsed'] * df_avgs['cores']
df = df.sort_values(by=['cores', 'trial'])

# construct pivot tables for elapsed time and time-per-core
df_pivot = pd.pivot_table(df, values='elapsed', index='cores', columns='trial')
df_pivot['mean'] = df_pivot.mean(axis=1, numeric_only=True)
df_pivot_norm = pd.pivot_table(df, values='cpu_time', index='cores', columns='trial')
df_pivot_norm['mean'] = df_pivot_norm.mean(axis=1, numeric_only=True)

# plot them and show
ax = plt.gca()
df_avgs.plot(kind='line', x='cores', y='elapsed', ax=ax)
df_avgs.plot(kind='line', x='cores', y='cpu_time', xlabel='# of Cores', ylabel='Runtime(s)', title='Avg. Runtime vs Avg. CPU Time', ax=ax)
df_pivot.plot(kind='bar', xlabel='# of Cores', ylabel='Runtime(s)', title='Runtime vs # of Cores')
df_pivot_norm.plot(kind='bar', xlabel='# of Cores', ylabel='CPU Time(s)', title='CPU Time vs # of Cores')
plt.show()
