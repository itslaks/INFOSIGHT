import os
import torch

torch_lib_path = os.path.join(os.path.dirname(torch.__file__), 'lib')
print("Contents of torch lib directory:")
print(os.listdir(torch_lib_path))