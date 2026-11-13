# Corrected scaffold notes

The first scaffold commit contained several file bodies at the wrong paths. This commit restores the intended Python package, test fixture, Terraform file roles, dashboard entry points, and ML package layout.

This repository is a demo scaffold. The SDK behavior and gRPC/ADWIN checks are stubs, the model training data is synthetic, and the dashboard does not display real test runs. The Terraform files require provider/API review and an authorized plan before any use. Do not apply to production.

Run Python checks from the repository root:

```sh
python -m pip install -r requirements.txt
python -m pip install -r shadow-core-dashboard/requirements.txt
PYTHONPATH=. pytest -q shadow-core-tests shadow-core-dashboard/test_main.py
```
