"""Heterogeneous GraphSAGE encoder and path-level embedding extractor."""

from __future__ import annotations

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.decomposition import PCA
from torch_geometric.data import HeteroData
from torch_geometric.nn import SAGEConv, to_hetero

from dbtrace.graph.builder import build_hetero_data
from dbtrace.schema import AccessPathRecord, CloudEnvironment


class _BaseGNN(nn.Module):
    def __init__(self, hidden_channels: int = 32) -> None:
        super().__init__()
        self.conv1 = SAGEConv((-1, -1), hidden_channels)
        self.conv2 = SAGEConv((-1, -1), hidden_channels)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.1, training=self.training)
        x = self.conv2(x, edge_index)
        return x


class HeteroPathEncoder:
    """Trains a heterogeneous GraphSAGE model and extracts fixed-size path embeddings."""

    def __init__(self, hidden_channels: int = 32, pca_dim: int = 16, seed: int = 42) -> None:
        self.hidden_channels = hidden_channels
        self.pca_dim = pca_dim
        self.seed = seed
        self.model: nn.Module | None = None
        self.head: nn.Module | None = None
        self.pca: PCA | None = None
        self._metadata: tuple | None = None
        self.epoch_history: list[dict[str, float]] = []

    def _init_model(self, sample_data: HeteroData) -> None:
        torch.manual_seed(self.seed)
        self._metadata = sample_data.metadata()
        self.model = to_hetero(_BaseGNN(self.hidden_channels), self._metadata, aggr="sum")
        # Path vector = [principal, compute, rds, db_role, db_table, principal*db_table] -> 6 * H
        self.head = nn.Sequential(
            nn.Linear(self.hidden_channels * 6, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
        )

    def _gather_path_vectors(
        self,
        emb_dict: dict[str, torch.Tensor],
        idx_maps: dict[str, dict[str, int]],
        paths: list[AccessPathRecord],
    ) -> torch.Tensor:
        vecs = []
        h = self.hidden_channels
        zero = torch.zeros(h, dtype=torch.float)
        for p in paths:
            hp = emb_dict["principal"][idx_maps["principal"][p.entry_principal_id]]
            hc = (
                emb_dict["compute"][idx_maps["compute"][p.compute_id]]
                if p.compute_id and p.compute_id in idx_maps["compute"]
                else zero
            )
            hr = emb_dict["rds"][idx_maps["rds"][p.rds_id]]
            hdbr = (
                emb_dict["db_role"][idx_maps["db_role"][p.db_role_id]]
                if p.db_role_id in idx_maps["db_role"]
                else zero
            )
            hdbt = emb_dict["db_table"][idx_maps["db_table"][p.db_table_id]]
            inter = hp * hdbt
            vecs.append(torch.cat([hp, hc, hr, hdbr, hdbt, inter], dim=-1))
        return torch.stack(vecs, dim=0)

    def fit(
        self,
        envs: dict[str, CloudEnvironment],
        paths_by_env: dict[str, list[AccessPathRecord]],
        train_env_ids: list[str],
        epochs: int = 50,
        lr: float = 3e-3,
    ) -> None:
        """Train GNN encoder ONLY on train_env_ids to prevent data leakage."""
        built = {eid: build_hetero_data(envs[eid]) for eid in train_env_ids}
        first_data, _ = built[train_env_ids[0]]
        self._init_model(first_data)
        assert self.model is not None and self.head is not None

        params = list(self.model.parameters()) + list(self.head.parameters())
        opt = torch.optim.Adam(params, lr=lr, weight_decay=1e-4)
        loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([8.0]))
        self.epoch_history = []

        self.model.train()
        self.head.train()
        for ep in range(1, epochs + 1):
            opt.zero_grad()
            total_loss = torch.tensor(0.0)
            n_used = 0
            for eid in train_env_ids:
                data, idx_maps = built[eid]
                epaths = paths_by_env[eid]
                if not epaths:
                    continue
                emb = self.model(data.x_dict, data.edge_index_dict)
                pvecs = self._gather_path_vectors(emb, idx_maps, epaths)
                logits = self.head(pvecs).squeeze(-1)
                y = torch.tensor([p.label_exploitable for p in epaths], dtype=torch.float)
                total_loss = total_loss + loss_fn(logits, y)
                n_used += 1
            total_loss.backward()
            opt.step()
            if ep == 1 or ep % 5 == 0:
                self.epoch_history.append({
                    "epoch": ep,
                    "loss": round(float(total_loss.item() / max(n_used, 1)), 4),
                })

        # Fit PCA on training path embeddings
        raw_train = self._encode_raw(envs, paths_by_env, train_env_ids)
        n_comp = min(self.pca_dim, raw_train.shape[0], raw_train.shape[1])
        self.pca = PCA(n_components=n_comp, random_state=self.seed)
        self.pca.fit(raw_train)

    @torch.no_grad()
    def _encode_raw(
        self,
        envs: dict[str, CloudEnvironment],
        paths_by_env: dict[str, list[AccessPathRecord]],
        env_ids: list[str],
    ) -> np.ndarray:
        assert self.model is not None
        self.model.eval()
        chunks = []
        for eid in env_ids:
            epaths = paths_by_env[eid]
            if not epaths:
                continue
            data, idx_maps = build_hetero_data(envs[eid])
            emb = self.model(data.x_dict, data.edge_index_dict)
            pvecs = self._gather_path_vectors(emb, idx_maps, epaths)
            chunks.append(pvecs.cpu().numpy())
        return np.vstack(chunks) if chunks else np.zeros((0, self.hidden_channels * 6))

    @torch.no_grad()
    def predict_gnn_proba(
        self,
        envs: dict[str, CloudEnvironment],
        paths_by_env: dict[str, list[AccessPathRecord]],
        env_ids: list[str],
    ) -> np.ndarray:
        assert self.model is not None and self.head is not None
        self.model.eval()
        self.head.eval()
        probs = []
        for eid in env_ids:
            epaths = paths_by_env[eid]
            if not epaths:
                continue
            data, idx_maps = build_hetero_data(envs[eid])
            emb = self.model(data.x_dict, data.edge_index_dict)
            pvecs = self._gather_path_vectors(emb, idx_maps, epaths)
            logits = self.head(pvecs).squeeze(-1)
            probs.append(torch.sigmoid(logits).cpu().numpy())
        return np.concatenate(probs) if probs else np.array([])

    def transform(
        self,
        envs: dict[str, CloudEnvironment],
        paths_by_env: dict[str, list[AccessPathRecord]],
        env_ids: list[str],
    ) -> np.ndarray:
        assert self.pca is not None
        raw = self._encode_raw(envs, paths_by_env, env_ids)
        return self.pca.transform(raw)

    def save_weights(self, path: str) -> None:
        assert self.model is not None and self.head is not None and self._metadata is not None
        torch.save(
            {
                "hidden_channels": self.hidden_channels,
                "pca_dim": self.pca_dim,
                "seed": self.seed,
                "metadata": self._metadata,
                "model_state": self.model.state_dict(),
                "head_state": self.head.state_dict(),
                "pca": self.pca,
            },
            path,
        )

    @classmethod
    def load_weights(cls, path: str, sample_data: HeteroData) -> HeteroPathEncoder:
        ckpt = torch.load(path, map_location="cpu", weights_only=False)
        enc = cls(hidden_channels=ckpt["hidden_channels"], pca_dim=ckpt["pca_dim"], seed=ckpt["seed"])
        enc._init_model(sample_data)
        assert enc.model is not None and enc.head is not None
        enc.model.load_state_dict(ckpt["model_state"])
        enc.head.load_state_dict(ckpt["head_state"])
        enc.pca = ckpt["pca"]
        return enc
