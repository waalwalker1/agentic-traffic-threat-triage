"""Compact PyTorch neural baseline model for session traffic threat estimation."""

import random

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from src.traffic_triage.features.extractor import FEATURE_NAMES, SessionFeatureVector


def set_torch_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.set_num_threads(1)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


class ThreatMLP(nn.Module):
    """Feed-forward neural architecture for traffic threat probability estimation."""

    def __init__(self, input_dim: int = len(FEATURE_NAMES), hidden_dim: int = 32) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class PyTorchThreatDetector:
    """CPU-runnable PyTorch detector wrapper with deterministic training."""

    def __init__(self, input_dim: int = len(FEATURE_NAMES), seed: int = 42) -> None:
        set_torch_seed(seed)
        self.model = ThreatMLP(input_dim=input_dim)
        self.mean: np.ndarray = np.zeros(input_dim, dtype=np.float32)
        self.std: np.ndarray = np.ones(input_dim, dtype=np.float32)
        self.is_trained = False

    def train_model(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epochs: int = 25,
        batch_size: int = 16,
        lr: float = 0.005,
    ) -> dict[str, float]:
        self.mean = np.mean(X, axis=0, dtype=np.float32)
        self.std = np.std(X, axis=0, dtype=np.float32)
        self.std[self.std < 1e-6] = 1.0

        X_norm = (X - self.mean) / self.std
        dataset = torch.utils.data.TensorDataset(
            torch.tensor(X_norm, dtype=torch.float32),
            torch.tensor(y, dtype=torch.float32).unsqueeze(1),
        )
        loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

        criterion = nn.BCELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=lr, weight_decay=1e-4)

        self.model.train()
        final_loss = 0.0
        for _epoch in range(epochs):
            total_loss = 0.0
            for batch_x, batch_y in loader:
                optimizer.zero_grad()
                pred = self.model(batch_x)
                loss = criterion(pred, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            final_loss = total_loss / len(loader)

        self.is_trained = True
        return {"final_loss": round(final_loss, 4), "epochs": epochs}

    def predict_score(self, fv: SessionFeatureVector) -> float:
        if not self.is_trained:
            return 0.5

        self.model.eval()
        with torch.no_grad():
            x = fv.to_array()
            x_norm = (x - self.mean) / self.std
            tensor_x = torch.tensor(x_norm, dtype=torch.float32).unsqueeze(0)
            score = self.model(tensor_x).item()
            return float(np.clip(score, 0.0, 1.0))
