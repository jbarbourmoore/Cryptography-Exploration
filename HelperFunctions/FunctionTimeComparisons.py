import time
from EllipticCurveCalculations import WeirrstrassCurveCalculations

import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
import time

def generateTimeData(functions_list, argument, labels_list, title):
     
    number_of_functions = len(functions_list)
    durations = []
    types = []
    numbers = []
    results_matrix = []

    for number in range(0, 10000, 25):
        results = []
        for i in range(0, number_of_functions):
            start_time = time.time()
            results.append(functions_list[i](argument,number))
            duration = time.time() - start_time
            durations.append(duration)
            types.append(labels_list[i])
            numbers.append(number)
        results_matrix.append(results)
        for i in range(0, number_of_functions):
            for j in range(i+1, number_of_functions):
                assert results[i]==results[j]

    dictionary ={
        "Duration": durations,
        "Method": types,
        "Number": numbers
    }

    dataframe = pd.DataFrame.from_dict(dictionary)
    
    fig, axes = plt.subplots(nrows=1, ncols=1, sharey=False)
    fig.set_figwidth(10)
    fig.set_figheight(6)

    bright_palette = sns.hls_palette(h=.5)

    sns.set_theme(style="whitegrid", palette=bright_palette)
    sns.scatterplot(data=dataframe, x="Number", y="Duration", ax=axes, hue="Method", palette=bright_palette[0:3])


    fig.canvas.manager.set_window_title(title=title)

    plt.tight_layout()
    plt.show()
    return dataframe, results_matrix

def generateGraphForEllipticCurveMultiplication():
    secp192r1 = WeirrstrassCurveCalculations(a=6277101735386680763835789423207666416083908700390324961276,
                                           b=2455155546008943817740293915197451784769108058161191238065,
                                           finite_field=6277101735386680763835789423207666416083908700390324961279 )
    point = (602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641)

    generateTimeData([secp192r1.calculatedPointMultiplicationByConstant_continualAddition,secp192r1.calculatedPointMultiplicationByConstant_doubleAndAddMethod],point,["Continual Addition", "Double and Add"], "Duration Comparisons For Elliptic Curve Point Multiplication")

generateGraphForEllipticCurveMultiplication()