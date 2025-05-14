#ifndef IOHelpers_HPP
#define IOHelpers_HPP

#include <iostream>
#include <fstream>
#include <vector>
#include <mutex>
using namespace std;

class CSVWriter{

    private :

        /// @brief The path of the file being written to
        string file_path_ {"out.csv"};

        /// @brief A mutex to prevent multiple threads from accessing the file simultaneously
        mutex * file_guard_ ;

        /// @brief The number of columns in the csv (populates based on the headers)
        int number_of_columns_ {1};

        /// @brief The headers for the csv
        vector<string> column_headers_ {};

    public : 

        /// @brief This method instantiates a CSV writer with a path, and given columns
        /// @param column_headers_ The column headers
        /// @param file_path optional - The file path to be written to (default is "out.csv")
        CSVWriter(vector<string> column_headers, string file_path = "out.csv");

        CSVWriter();

        /// @brief This method writes content as a line in a csv
        /// @param content The vector of string content to be written
        void writeContent(vector<string> content);

        /// @brief This method writes the headers as a line in the csv
        void writeHeaders();

        /// @brief This method writes a string line in the file
        /// @param line The line to be written
        void writeLineToFile(string line);

};

#endif