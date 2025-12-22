import torch

from simple_worm.losses import N_REG_LOSSES, REG_LOSS_TYPES, REG_LOSS_VARS


class LossesTorch:
    """
    Parameter holder for the data and regularisation losses.
    """

    def __init__(self, losses: torch.Tensor):
        self.losses = losses.clone()

        # Handle batches of losses
        if losses.ndim == 2:
            self.batch_size = losses.shape[0]
            losses = losses.transpose(0, 1)
        else:
            assert losses.ndim == 1
            self.batch_size = 0

        self.total = losses[0]
        self.data = losses[1]
        self.reg = losses[2]

        rv_weighted = losses[3:3 + N_REG_LOSSES]
        rv_unweighted = losses[3 + N_REG_LOSSES:3 + N_REG_LOSSES * 2]
        reg_losses_weighted = {}
        reg_losses_unweighted = {}
        i = 0
        for loss in REG_LOSS_TYPES:
            reg_losses_weighted[loss] = {}
            reg_losses_unweighted[loss] = {}
            for k in REG_LOSS_VARS:
                reg_losses_weighted[loss][k] = rv_weighted[i]
                reg_losses_unweighted[loss][k] = rv_unweighted[i]
                i += 1

        self.reg_losses_weighted = reg_losses_weighted
        self.reg_losses_unweighted = reg_losses_unweighted

    def __getitem__(self, i) -> 'LossesTorch':
        """
        Retrieve losses for a single element from a batch.
        """
        assert self.batch_size != 0, 'LossesTorch instance has no batch dimension to index into.'
        if i < 0 or i > self.batch_size:
            raise IndexError(f'Index = {i} not available in the batch.')
        return LossesTorch(self.losses[i])
