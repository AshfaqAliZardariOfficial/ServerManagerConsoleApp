using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerManagerConsoleApp
{
    /// <summary>
    /// Static class to write and delete files.
    /// </summary>
    public static class FileManager
    {
        /// <summary>
        /// Write a message in file.
        /// </summary>
        /// <param name="message">Message to be written.</param>
        /// <param name="filePath">File path (Default: LogsFile.txt).</param>
        /// <param name="useProjectRootDirectory">Use project directory or FilePath (Default: Project Directory).</param>
        /// <param name="appendMessage"></param>
        /// <returns>true if the message is written, otherwise false.</returns>
        public static bool WriteMessage(string message, string filePath = "LogsFile.txt", bool useProjectRootDirectory = true, bool appendMessage = true)
        {
            bool _isMessageWritten = false;
            filePath = useProjectRootDirectory ? string.Format("{0}\\{1}", Directory.GetCurrentDirectory().Replace("bin\\Debug", ""), filePath) : filePath;
            try
            {
                if (File.Exists(filePath))
                {
                    using (var _tw = new StreamWriter(filePath, appendMessage))
                    {
                        _tw.WriteLine(message);
                    }
                }
                else
                {
                    using (StreamWriter _sw = File.CreateText(filePath)) { };
                    TextWriter _tw = new StreamWriter(filePath, appendMessage);
                    _tw.WriteLine(message);
                    _tw.Close();
                }
                _isMessageWritten = true;
            }
            catch (Exception)
            {

            }
            return _isMessageWritten;
        }
        /// <summary>
        /// Delete a file.
        /// </summary>
        /// <param name="filePath">File path (Default: LogsFile.txt).</param>
        /// <param name="useProjectRootDirectory">Use project directory or FilePath (Default: Project Directory).</param>
        /// <returns>true if the file is deleted, otherwise false.</returns>
        public static bool DeleteFile(string filePath = "LogsFile.txt", bool useProjectRootDirectory = true)
        {
            bool _isFileDeleted = false;
            filePath = useProjectRootDirectory ? string.Format("{0}\\{1}", Directory.GetCurrentDirectory().Replace("bin\\Debug", ""), filePath) : filePath;
            try
            {
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    _isFileDeleted = true;
                }
            }
            catch (Exception)
            {

            }
            return _isFileDeleted;
        }
        /// <summary>
        /// Check the file exist or not.
        /// </summary>
        /// <param name="filePath">File path (Default: LogsFile.txt).</param>
        /// <param name="useProjectRootDirectory">Use project directory or FilePath (Default: Project Directory).</param>
        /// <returns></returns>
        public static bool IsFileExist(string filePath = "LogsFile.txt", bool useProjectRootDirectory = true)
        {
            filePath = useProjectRootDirectory ? string.Format("{0}\\{1}", Directory.GetCurrentDirectory().Replace("bin\\Debug", ""), filePath) : filePath;
            try
            {
                return File.Exists(filePath);
            }
            catch (Exception)
            {

            }
            return false;
        }
        /// <summary>
        /// Read message of the file.
        /// </summary>
        /// <param name="filePath">File path (Default: LogsFile.txt).</param>
        /// <param name="useProjectRootDirectory">Use project directory or FilePath (Default: Project Directory).</param>
        /// <returns></returns>
        public static string ReadMessage(string filePath = "LogsFile.txt", bool useProjectRootDirectory = true)
        {
            filePath = useProjectRootDirectory ? string.Format("{0}\\{1}", Directory.GetCurrentDirectory().Replace("bin\\Debug", ""), filePath) : filePath;
            try
            {
                if (File.Exists(filePath))
                {
                    return File.ReadAllText(filePath);
                }
            }
            catch (Exception)
            {

            }
            return null;
        }
    }
}
