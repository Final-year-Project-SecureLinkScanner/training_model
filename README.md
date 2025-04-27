# Machine Learning Model Training Project

This project focuses on training and evaluating machine learning models to achieve optimal performance for a specific task. The repository contains scripts, datasets, and configurations used to train and compare multiple models. The final chosen model, **Final_Grid_model3_IMP,pkl**, was selected based on its superior performance metrics and robustness compared to other models.

## Project Structure

- **`Dataset/`**: Contains the datasets used for training and testing the models.
- **`Models/`**: Stores the trained models and their configurations.
- **`scripts/`**: Includes Python scripts for data preprocessing, model training, evaluation, and hyperparameter tuning.

## Key Steps in the Project

1. **Data Preprocessing**:
    - Cleaned and normalised the dataset to ensure consistency.
    - Split the data into training, validation, and testing sets.

2. **Model Training**:
    - Multiple models were trained using different algorithms and hyperparameter configurations.
    - Techniques such as cross-validation and grid search were employed to optimise performance.

3. **Evaluation**:
    - Models were evaluated using metrics such as accuracy, precision, recall, F1-score, and AUC-ROC.
    - Results were logged and visualised for comparison.

4. **Model Selection**:
    - The final model was chosen based on its performance on the validation and test datasets.

## Why Final_Grid_model3_IMP.pkl Was Chosen

Grid Model 3 (Improved) was selected over other models due to the following reasons:
- **Performance**: It achieved the highest accuracy and F1-score among all tested models.
- **Generalisation**: Demonstrated robust performance on unseen test data, indicating good generalisation.
- **Hyperparameter Optimisation**: The improved version of Grid Model 3 incorporated fine-tuned hyperparameters, leading to better results.
- **Efficiency**: Despite its complexity, the model's training and inference times were reasonable.

## How to Use This Project

1. Clone the repository:
    ```
    git clone <repository-url>
    ```
2. Install the required dependencies:
    ```
    pip install -r requirements.txt
    ```
3. Run the preprocessing script:
    ```
    python scripts/preprocess_data.py
    ```
4. Train the models:
    ```
    python scripts/train_models.py
    ```
5. Evaluate the final model:
    ```
    python scripts/evaluate_model.py --model models/grid_model_3_improved.pkl
    ```

## Future Work

- Experiment with additional algorithms and architectures.
- Explore advanced techniques like ensemble learning.
- Optimize the pipeline for scalability and deployment.

## Acknowledgments

Special thanks to the contributors and resources that supported this project.