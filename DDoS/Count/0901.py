# -*- coding: utf-8 -*-
"""0829.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1sAS5lxNi9g1E5-dsFuai5uSpXGTchw1x
"""
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import numpy as np
import pandas as pd

df = pd.read_csv('C:/Users/admin/Documents/code/0620.csv', sep = ",", low_memory=False)

df

K = df.copy()

K['time']

K['time'].replace(':','',regex=True, inplace=True)

K['time'].astype('float')

test = K[['Fwd Header Len', 'Tot Fwd Pkts', 'Fwd Seg Size Avg',
             'Subflow Fwd Byts', 'Init Bwd Win Byts', 'Fwd Pkt Len Std', 'Flow IAT Std',
            'Bwd IAT Min', 'Bwd Seg Size Avg', 'ACK Flag Cnt', 'Tot Bwd Pkts', 'Bwd Pkt Len Mean', 'Pkt Len Mean',
         'Pkt Len Max', 'Subflow Bwd Pkts', 'Flow IAT Min', 'TotLen Bwd Pkts', 'Bwd Pkt Len Std', 'Flow IAT Max', 'Flow Duration', 'Fwd IAT Tot', 'DDOS']]



test = test.sample(frac=0.1)

x = test.drop(['DDOS'], axis =1)
y = test['DDOS']
test_dataset = test.sample(frac=0.3)

from sklearn.model_selection import train_test_split

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3)

print(x_train.shape)

print(x_test.shape)
print(y_train.shape)

print(y_test.shape)

y_train = y_train.to_numpy()
y_test = y_test.to_numpy()

y_train.shape

y_test.shape

y_train = y_train.reshape(-1,1)
y_test = y_test.reshape(-1,1)

y_train.shape

y_test.shape

print(x_train.shape)
print(x_test.shape)
print(y_train.shape)
print(y_test.shape)

y_test

y_test = pd.DataFrame(y_test)

y_train = pd.DataFrame(y_train)

y_test

x_train = np.array(x_train)
y_train = np.array(y_train)

x_test = np.array(x_test)
y_test = np.array(y_test)

x_train.shape

print(x_train.shape)
print(y_train.shape)
print(x_test.shape)

x_train = np.reshape(x_train, (73278, 1, 21))
x_test = np.reshape(x_test, (31406, 1, 21))

x_train.shape
from keras.layers import Input, LSTM, Dense, TimeDistributed, Activation, BatchNormalization, Dropout, Bidirectional

# from keras.utils import Sequence
from keras.layers import CuDNNLSTM
# from tensorflow.keras.utils import Sequence
import pandas as pd
import os
import tensorflow as tf
# os.environ["CUDA_VISIBLE_DEVICES"]="0"
# gpus = tf.config.experimental.list_physical_devices('GPU')
# if gpus:
#     try:
#         tf.config.experimental.set_memory_growth(gpus[0], True)
#     except RuntimeError as e:
#         print(e)

# physical_devices = tf.config.experimental.list_physical_devices('GPU')
# tf.config.experimental.set_memory_growth(physical_devices[0], True)

import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import tensorflow as tf

import tensorflow.compat.v1 as tf


from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, LSTM

from tensorflow.compat.v1.keras.layers import CuDNNLSTM

import tensorflow.compat.v1 as tf

physical_devices = tf.config.experimental.list_physical_devices('GPU')
tf.config.experimental.set_memory_growth(physical_devices[0], True)

# 1. 저장할 폴더와 형식을 선택
folder_directory ="C:/Users/admin/Desktop/Sdata"
checkPoint_path = folder_directory + "/model_{epoch}.ckpt"  # 저장할 당시 epoch가 파일이름이 된다.

# 2. 콜백 변수를 생성
my_period =1000
cp_callback = tf.keras.callbacks.ModelCheckpoint(filepath=checkPoint_path,
                                                 save_weights_only=True, verbose=1, period=my_period)







model = Sequential()

model.add(LSTM(128, input_shape=(1,21), return_sequences=True))
model.add(Dropout(0.2))

model.add(LSTM(128))
model.add(Dropout(0.1))

model.add(Dense(32, activation='relu'))
model.add(Dropout(0.2))

model.add(Dense(1, activation='sigmoid'))

opt = tf.keras.optimizers.Adam(learning_rate=0.01, decay=1e-6)

model.compile(
    loss='binary_crossentropy',
    optimizer=opt,
    metrics=['accuracy'],
)

model.fit(x_train,
          y_train,
          batch_size=512,
          epochs=100000,
          callbacks=[cp_callback],
          verbose=1,
          validation_data=(x_test, y_test)
          )



loss,acc = model.evaluate(x_test, y_test, verbose = 1)

prediction = model.predict(x_test)

prediction[10]

threshold = 0.5

prediction_2 = np.where(prediction >= threshold, 1, prediction)
prediction_2 = np.where(prediction_2 < threshold, 0, prediction_2)

prediction_2

cm = confusion_matrix(y_test, prediction_2)
print(cm)

print("True Negative TN : ", cm[0][0])

print("False Positive FP : ", cm[0][1])

print("False Negative FN : ", cm[1][0])

print("True Positive TP : ", cm[1][1])

print("Detection Rate is : ", (cm[1][1])/(cm[1][1]+cm[1][0])*100)

print("False Alarm Rate is : ", (cm[0][1])/(cm[0][1]+cm[0][0])*100)

print(classification_report(y_test, prediction_2, digits=5))

# from keras.model import load_model

model.save('0925.h5')