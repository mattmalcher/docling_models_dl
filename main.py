from pathlib import Path

from docling.models.layout_model import LayoutModel
from docling.models.table_structure_model import TableStructureModel
from docling.utils.model_downloader import download_models

from validator import (
    generate_folder_structure,
    load_structure_from_json,
    save_structure_to_json,
    validate_structure,
)

# different add-ins described at:
# https://docling-project.github.io/docling/usage/enrichments/

# download_models at: https://github.com/docling-project/docling/blob/f94da44ec5c7a8c92b9dd60e4df5dc945ed6d1ea/docling/utils/model_downloader.py

model_folder= "./docling_models"


# run to update the strcutre json file
if False:
    download_models(
        output_dir=Path(model_folder),

        with_layout=True,
        with_tableformer=True,

        with_code_formula=False, # for parsing of code blocks & maths formulae in the document 
        with_easyocr=False,
        with_granite_vision=False,
        with_picture_classifier=False, # annotate a picture with a vision model - if using a local model. We could use remote vision model
        with_smolvlm=False,
    )
    structure = generate_folder_structure(model_folder)
    save_structure_to_json(structure, "docling_models.json")
else:
    structure = load_structure_from_json("docling_models.json")


layout_model_info = {
    "path":LayoutModel._model_path,
    "repo_folder":LayoutModel._model_repo_folder,
    }


table_model_info = {
    "path":TableStructureModel._model_path,
    "repo_folder":TableStructureModel._model_repo_folder,
    }



comparison = validate_structure(model_folder, structure)

print("done")