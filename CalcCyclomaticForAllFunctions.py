try:
    from typing import cast
    from ghidra_builtins import *
except Exception as e:
    pass

from ghidra.app.tablechooser import (
    AddressableRowObject,
    StringColumnDisplay,
    TableChooserDialog,
)
from ghidra.program.util import CyclomaticComplexity
import re


def get_functions_list():
    
    functions = currentProgram.getFunctionManager().getFunctions(
        True
    )

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
#     regex = r'^((complexity|frequency+[<>=][0-9]+){1}(;(complexity|frequency)+[<>=][0-9]+){0,2})?'
#     regex = re.compile(regex)
    
#     choices = [
#         "Show All"
#         "Filter functions with a expression"
#     ]
    
#     user_choice = askChoice("Choose One", "Select one", choices,1)
#     user_option = choices.index(user_choice)
    
#     result = []
    
#     if user_choice == 0:
#         number = askInt(user_choice, "Enter the 'n' value")
        
#     elif user_choice == 1:
#         number = askInt(user_choice, "Enter the 'n' value")
        
    result = get_functions_list()
    
    table_dialog = createTableChooserDialog(
        "Functions with Complexity and Frequency",
        cast(TableChooserDialog, None),
    )
    configure_table_columns(table_dialog)
    table_dialog.show()
    
    for i in result:
        table_dialog.add(
            ComplexFunction(
                i["function"], i["address"], i["complexity"], i["frequency"]
            )
        )