import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Define P30 values
P30_values = np.array([0.01] + list(np.arange(0.1, 1.1, 0.1)))  # From 0.01, 0.1, 0.2, ..., 1.0

# Calculate approximate and exact P1 values
P1_approx = P30_values / 30.0
P1_exact = 1 - (1 - P30_values) ** (1 / 30.0)

# Calculate absolute and relative errors
abs_error = np.abs(P1_exact - P1_approx)
rel_error = abs_error / P1_exact

# Create a DataFrame for display
df = pd.DataFrame({
    'P30': P30_values,
    'P1 Approx (P30/30)': P1_approx,
    'P1 Exact (1-(1-P30)^(1/30))': P1_exact,
    'Absolute Error': abs_error,
    'Relative Error (%)': rel_error * 100
})

# Display the DataFrame
import ace_tools as tools; tools.display_dataframe_to_user(name="Comparison of Approximate vs Exact P1", dataframe=df)

# Create a plot for relative error percentage vs P30
plt.figure()
plt.plot(P30_values, rel_error * 100, marker='o', linestyle='-')
plt.xlabel('P30')
plt.ylabel('Relative Error (%)')
plt.title('Relative Error of Approximation (P1≈P30/30) vs P30')
plt.grid(True)
plt.show()
