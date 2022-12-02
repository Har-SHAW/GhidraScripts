try:
    from ghidra_builtins import *
except Exception as e:
    pass

from ghidra.app.tablechooser import (
    AddressableRowObject,
    StringColumnDisplay,
)

from ghidra.program.util import CyclomaticComplexity


def get_functions_list():
    
    functions = currentProgram.getFunctionManager().getFunctions(True)

    func_list = []
    metric = CyclomaticComplexity()
    for function in functions:
        complexity = metric.calculateCyclomaticComplexity(function, monitor)
        frequency = len(function.getCallingFunctions(monitor))
        if(complexity > 0):
            func_list.append(
                {
                    "function": str(function),
                    "address": function.getEntryPoint(),
                    "complexity": complexity,
                    "frequency": frequency
                }
        )
        
    return func_list

def top_n_complex(func_list, n):
    sorted_func_list = sorted(
        func_list, key=lambda elem: elem["complexity"], reverse=True
    )
    
    return sorted_func_list[:n]

def top_n_frequent(func_list, n):
    sorted_func_list = sorted(
        func_list, key=lambda elem: elem["frequency"], reverse=True
    )
    
    return sorted_func_list[:n]
    

class ComplexFunction(AddressableRowObject):
    def __init__(
        self, function_name, location, complexity, frequency
    ):
        super(ComplexFunction, self).__init__()
        self.function_name = function_name
        self.location = location
        self.complexity = complexity
        self.frequency = frequency

    def getAddress(self):
        return self.location


class FunctionNameColumn(StringColumnDisplay):
    def getColumnName(self):
        return u"Function Name"

    def getColumnValue(
        self, row_object
    ):
        return row_object.function_name


class ComplexityColumn(StringColumnDisplay):
    def getColumnName(self):
        return u"Complexity"

    def getColumnValue(
        self, row_object
    ):
        return row_object.complexity
    
class FrequencyColumn(StringColumnDisplay):
    def getColumnName(self):
        return u"Frequency"

    def getColumnValue(
        self, row_object
    ):
        return row_object.frequency


def configure_table_columns(table_dialog):
    table_dialog.addCustomColumn(FunctionNameColumn())
    table_dialog.addCustomColumn(ComplexityColumn())
    table_dialog.addCustomColumn(FrequencyColumn())



if __name__ == "__main__":
    choices = [
        "Show All",
        "Show top 10 cyclomatically complex functions",
        "Show top 10 frequently used functions",
        "Show top 50 cyclomatically complex functions",
        "Show top 50 frequently used functions"
    ]
    
    user_choice = askChoice("Choose One", "Select one", choices,1)
    user_option = choices.index(user_choice)
    
    result = get_functions_list()
    
    if user_option == 1:
        result = top_n_complex(result, 10)
        
    elif user_option == 2:
        result = top_n_frequent(result, 10)
        
    elif user_option == 3:
        result = top_n_complex(result, 50)
        
    elif user_option == 4:
        result = top_n_frequent(result, 50)
    
    table_dialog = createTableChooserDialog(
        "Functions with Cyclomatic Complexity and Frequency",
        None,
    )
    
    configure_table_columns(table_dialog)
    table_dialog.show()
    
    for i in result:
        table_dialog.add(
            ComplexFunction(
                i["function"], i["address"], i["complexity"], i["frequency"]
            )
        )