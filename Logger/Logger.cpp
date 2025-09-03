#include <stdio.h>
#include <time.h>
#include <fstream>
#include <iostream>

#include "Logger.h"
#include "util.h"

bool LogLevel::isValid(int level)
{
	switch(level) {
		case Info:
		case Error:
		case Debug:
			return true;
		default:
			return false;
	}
}

std::string LogLevel::toString(int level)
{
	switch(level) {
		case Info:
			return "Info";
		case Error:
			return "Error";
		case Debug:
			return "Debug";
        case Warning:
            return "Warning";
	}

	return "";
}

std::string Logger::_logFile = "";
std::ofstream Logger::_logFileStream;

std::string Logger::getDateTimeString()
{
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);

	strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

	return std::string(buf);
}

std::string Logger::formatLog(int logLevel, std::string msg)
{
	std::string dateTime = getDateTimeString();

	std::string prefix = "[" + dateTime + "] [" + LogLevel::toString(logLevel) + "] ";

	size_t prefixLen = prefix.length();

	std::string padding(prefixLen, ' ');

	if(msg.find('\n', 0) != std::string::npos) {
 		size_t pos = 0;
		size_t prev = 0;

		while((pos = msg.find('\n', prev)) != std::string::npos) {
			prefix += msg.substr(prev, pos - prev) + "\n" + padding;
			prev = pos + 1;
		}

		prefix += msg.substr(prev);
	} else {
		prefix += msg;
	}

	return prefix;
}


void Logger::log(int logLevel, std::string msg)
{
	std::string str = formatLog(logLevel, msg);

	fprintf(stderr, "%s\n", str.c_str());
	
	// Also write to log file if set
	logToFile(logLevel, msg);
}

void Logger::setLogFile(std::string path)
{
    if(_logFileStream.is_open()) {
        _logFileStream.close();
    }
    
    _logFile = path;
    if(!_logFile.empty()) {
        _logFileStream.open(_logFile.c_str(), std::ios::app);
        if(!_logFileStream.is_open()) {
            std::cerr << "Failed to open log file: " << _logFile << std::endl;
        }
    }
}

void Logger::logToFile(int logLevel, std::string msg)
{
    if(!_logFile.empty() && _logFileStream.is_open()) {
        std::string str = formatLog(logLevel, msg);
        _logFileStream << str << std::endl;
        _logFileStream.flush();
    }
}
