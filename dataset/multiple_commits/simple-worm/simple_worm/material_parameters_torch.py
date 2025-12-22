from typing import List, Union, Dict

import torch

from simple_worm.material_parameters import MaterialParameters, MP_KEYS, MaterialParametersFenics, MP_DEFAULT_K, \
    MP_DEFAULT_K_ROT, MP_DEFAULT_A, MP_DEFAULT_B, MP_DEFAULT_C, MP_DEFAULT_D, MP_BOUNDS, GT, GTE, LT, LTE


def mp_fenics_to_torch(self) -> 'MaterialParametersTorch':
    args = {k: float(getattr(self, k)) for k in MP_KEYS}
    return MaterialParametersTorch(**args)


MaterialParametersFenics.to_torch = mp_fenics_to_torch


class MaterialParametersTorch(MaterialParameters):
    """
    Material parameters.
    """

    def __init__(
            self,
            K: torch.Tensor = torch.tensor(MP_DEFAULT_K),
            K_rot: torch.Tensor = torch.tensor(MP_DEFAULT_K_ROT),
            A: torch.Tensor = torch.tensor(MP_DEFAULT_A),
            B: torch.Tensor = torch.tensor(MP_DEFAULT_B),
            C: torch.Tensor = torch.tensor(MP_DEFAULT_C),
            D: torch.Tensor = torch.tensor(MP_DEFAULT_D),
            optimise_K: bool = False,
            optimise_K_rot: bool = False,
            optimise_A: bool = False,
            optimise_B: bool = False,
            optimise_C: bool = False,
            optimise_D: bool = False,
    ):
        # Ensure values are tensors
        if not isinstance(K, torch.Tensor):
            K = torch.tensor(K, dtype=torch.float64)
        if not isinstance(K_rot, torch.Tensor):
            K_rot = torch.tensor(K_rot, dtype=torch.float64)
        if not isinstance(A, torch.Tensor):
            A = torch.tensor(A, dtype=torch.float64)
        if not isinstance(B, torch.Tensor):
            B = torch.tensor(B, dtype=torch.float64)
        if not isinstance(C, torch.Tensor):
            C = torch.tensor(C, dtype=torch.float64)
        if not isinstance(D, torch.Tensor):
            D = torch.tensor(D, dtype=torch.float64)

        self.optimise_K = optimise_K
        self.optimise_K_rot = optimise_K_rot
        self.optimise_A = optimise_A
        self.optimise_B = optimise_B
        self.optimise_C = optimise_C
        self.optimise_D = optimise_D
        super().__init__(K, K_rot, A, B, C, D)

        # Ensure parameters require grad if needed
        if self.optimise_K:
            self.K.requires_grad = True
        if self.optimise_K_rot:
            self.K_rot.requires_grad = True
        if self.optimise_A:
            self.A.requires_grad = True
        if self.optimise_B:
            self.B.requires_grad = True
        if self.optimise_C:
            self.C.requires_grad = True
        if self.optimise_D:
            self.D.requires_grad = True

    def _validate(self):
        super()._validate()

        # Ensure values are singular
        assert self.K.ndim == 0
        assert self.K_rot.ndim == 0
        assert self.A.ndim == 0
        assert self.B.ndim == 0
        assert self.C.ndim == 0
        assert self.D.ndim == 0

    def clamp(self, eps: float = 1e-5):
        """
        Update the values to ensure they all sit within the bounds.
        """
        for k in MP_KEYS:
            v = getattr(self, k)
            bounds = MP_BOUNDS[k]
            if bounds['LB_TYPE'] == GT:
                v.data = v.clamp(min=bounds['LB'] + eps)
            elif bounds['LB_TYPE'] == GTE:
                v.data = v.clamp(min=bounds['LB'])
            if bounds['UB_TYPE'] == LT:
                v.data = v.clamp(max=bounds['UB'] - eps)
            elif bounds['UB_TYPE'] == LTE:
                v.data = v.clamp(max=bounds['UB'])

    def parameters(self, as_dict=False) -> Union[List[torch.Tensor], Dict[str, torch.Tensor]]:
        if as_dict:
            return {k: getattr(self, k) for k in MP_KEYS}
        else:
            return [getattr(self, k) for k in MP_KEYS]

    def parameter_vector(self) -> torch.Tensor:
        return torch.stack(self.parameters())

    def requires_grad(self) -> bool:
        return any(getattr(self, k).requires_grad for k in MP_KEYS)

    def clone(self) -> 'MaterialParametersTorch':
        args = {k: getattr(self, k).clone() for k in MP_KEYS}
        return MaterialParametersTorch(**args)

    def __eq__(self, other: 'MaterialParametersTorch') -> bool:
        return all(
            torch.allclose(getattr(self, k), getattr(other, k))
            for k in MP_KEYS
        )


class MaterialParametersBatchTorch(MaterialParametersTorch):
    def _validate(self):
        # Ensure values are vectors
        assert self.K.ndim == 1
        assert self.K_rot.ndim == 1
        assert self.A.ndim == 1
        assert self.B.ndim == 1
        assert self.C.ndim == 1
        assert self.D.ndim == 1

        # Ensure values all have the same batch size
        assert self.K.shape == self.K_rot.shape == self.A.shape == self.B.shape == self.C.shape == self.D.shape

        # Validate each entry in the batch
        bs = self.K.shape[0]
        for i in range(bs):
            MaterialParameters._validate(self[i])

    def clone(self) -> 'MaterialParametersBatchTorch':
        args = {k: getattr(self, k).clone() for k in MP_KEYS}
        return MaterialParametersBatchTorch(**args)

    def __getitem__(self, i) -> MaterialParametersTorch:
        args = {k: getattr(self, k)[i] for k in MP_KEYS}
        return MaterialParametersTorch(**args)

    def __len__(self) -> int:
        return self.K.shape[0]

    @staticmethod
    def from_list(
            batch: List[MaterialParametersTorch],
            optimise_K: bool = False,
            optimise_K_rot: bool = False,
            optimise_A: bool = False,
            optimise_B: bool = False,
            optimise_C: bool = False,
            optimise_D: bool = False
    ) -> 'MaterialParametersBatchTorch':
        args = {
            k: torch.stack([getattr(batch[i], k) for i in range(len(batch))])
            for k in MP_KEYS
        }
        return MaterialParametersBatchTorch(
            **args,
            optimise_K=optimise_K,
            optimise_K_rot=optimise_K_rot,
            optimise_A=optimise_A,
            optimise_B=optimise_B,
            optimise_C=optimise_C,
            optimise_D=optimise_D,
        )
