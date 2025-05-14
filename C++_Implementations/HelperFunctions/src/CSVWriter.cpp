#include "IOHelpers.hpp"

CSVWriter::CSVWriter(vector<string> column_headers, string file_path){
    column_headers_ = column_headers;
    file_path_ = file_path;
    number_of_columns_ = column_headers.size();
}

void CSVWriter::writeContent(vector<string> content){
    // pad the content with empty if it is smaller than the number of the columns
    if (content.size() < number_of_columns_){
        int number_empty = content.size() < number_of_columns_;
        for (int i = 0; i < number_empty; i++){
            content.push_back("");
        }
    }

    // create a single comma delineated string of the content
    string content_line = "";
    for (int i = 0; i < number_of_columns_; i++){
        content_line.append(content[i]);
        content_line.append(",");
    }

    // write the single string to the file
    writeLineToFile(content_line);
}

void CSVWriter::writeHeaders(){
    writeContent(column_headers_);
}

void CSVWriter::writeLineToFile(string line){
    // open the csv file in appending mode and write a line before closing
    ofstream csv_file;
    csv_file.open(file_path_, ios::out | ios::app);
    csv_file << line;
    csv_file << "\n";
    csv_file.close();
}