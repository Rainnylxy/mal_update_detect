from simple_worm.trainer import Trainer


def train_inv(
        optim_MP_K: bool = False,
        optim_MP_K_rot: bool = False,
        optim_MP_A: bool = False,
        optim_MP_B: bool = False,
        optim_MP_C: bool = False,
        optim_MP_D: bool = False,
        optim_F0=False,
        optim_CS=False,
        N=4,
        T=0.2,
        dt=0.1,
        lr=0.5,
        n_steps=1,
        inverse_opt_max_iter=1,
        save_videos=False,
        save_plots=False
):
    print('\n==== Test Inverse Trainer ===')
    id_str = f'optim_MP_K={optim_MP_K},' \
             f'optim_MP_K_rot={optim_MP_K_rot},' \
             f'optim_MP_A={optim_MP_A},' \
             f'optim_MP_B={optim_MP_B},' \
             f'optim_MP_C={optim_MP_C},' \
             f'optim_MP_D={optim_MP_D},' \
             f'optim_F0={optim_F0},' \
             f'optim_CS={optim_CS}'
    print(id_str.replace(',', ', ') + '\n')

    trainer = Trainer(
        N=N,
        T=T,
        dt=dt,
        optim_MP_K=optim_MP_K,
        optim_MP_K_rot=optim_MP_K_rot,
        optim_MP_A=optim_MP_A,
        optim_MP_B=optim_MP_B,
        optim_MP_C=optim_MP_C,
        optim_MP_D=optim_MP_D,
        optim_F0=optim_F0,
        optim_CS=optim_CS,
        target_params={'alpha_pref_freq': 1, 'beta_pref_freq': 0.5},
        lr=lr,
        reg_weights={},
        inverse_opt_max_iter=inverse_opt_max_iter,
        save_videos=save_videos,
        save_plots=save_plots,
    )
    trainer.train(n_steps)
    print('done')


default_args = {
    'optim_MP_K': False,
    'optim_MP_K_rot': False,
    'optim_MP_A': False,
    'optim_MP_B': False,
    'optim_MP_C': False,
    'optim_MP_D': False,
    'optim_F0': False,
    'optim_CS': False,
    'N': 20,
    'dt': 0.1,
    'T': 0.3,
    'lr': 1e-1,
    'n_steps': 3,
    'inverse_opt_max_iter': 1,
    'save_videos': False,
    'save_plots': False,
}


def test_inv_trainer_none():
    train_inv(**default_args)


def test_inv_trainer_MP_K():
    train_inv(**{**default_args, 'optim_MP_K': True})


def test_inv_trainer_MP_K_rot():
    train_inv(**{**default_args, 'optim_MP_K_rot': True})


def test_inv_trainer_MP_A():
    train_inv(**{**default_args, 'optim_MP_A': True})


def test_inv_trainer_MP_B():
    train_inv(**{**default_args, 'optim_MP_B': True})


def test_inv_trainer_MP_C():
    train_inv(**{**default_args, 'optim_MP_C': True})


def test_inv_trainer_MP_D():
    train_inv(**{**default_args, 'optim_MP_D': True})


def test_inv_trainer_MP_all():
    train_inv(**{**default_args,
                 'optim_MP_K': True,
                 'optim_MP_K_rot': True,
                 'optim_MP_A': True,
                 'optim_MP_B': True,
                 'optim_MP_C': True,
                 'optim_MP_D': True})


def test_inv_trainer_F0():
    train_inv(**{**default_args, 'optim_F0': True})


def test_inv_trainer_CS():
    train_inv(**{**default_args, 'optim_CS': True})


def test_inv_trainer_all():
    train_inv(**{**default_args,
                 'optim_MP_K': True,
                 'optim_MP_K_rot': True,
                 'optim_MP_A': True,
                 'optim_MP_B': True,
                 'optim_MP_C': True,
                 'optim_MP_D': True,
                 'optim_F0': True,
                 'optim_CS': True})


if __name__ == '__main__':
    test_inv_trainer_none()
    test_inv_trainer_MP_K()
    test_inv_trainer_MP_K_rot()
    test_inv_trainer_MP_A()
    test_inv_trainer_MP_B()
    test_inv_trainer_MP_C()
    test_inv_trainer_MP_D()
    test_inv_trainer_MP_all()
    test_inv_trainer_F0()
    test_inv_trainer_CS()
    test_inv_trainer_all()
