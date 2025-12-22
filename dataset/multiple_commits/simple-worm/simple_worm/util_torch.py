from typing import List
from typing import Union

import numpy as np
import torch
from fenics import *
from fenics_adjoint import *

from simple_worm.util import f2n, v2f


def t2n(var: torch.Tensor) -> np.ndarray:
    """
    Torch to Numpy
    """
    return var.detach().numpy()


def f2t(var: Union[Function, List[Function]]) -> torch.Tensor:
    """
    Fenics to Torch
    Returns a torch tensor containing fenics function values
    """
    return torch.from_numpy(f2n(var))


def t2f(
        val: torch.Tensor,
        var: Function = None,
        fs: FunctionSpace = None,
        name: str = None
) -> Function:
    """
    Torch to Fenics
    Set a value to a new or existing fenics variable.
    """
    val = t2n(val)
    return v2f(val, var, fs, name)


def expand_tensor(v: torch.Tensor, size: int = 1) -> torch.Tensor:
    """
    Expand a torch tensor along a new dimension prepended to the front.
    """
    v = v.unsqueeze(0)
    if size > 1:
        v = v.expand(size, *v.shape[1:]).clone()
    return v
