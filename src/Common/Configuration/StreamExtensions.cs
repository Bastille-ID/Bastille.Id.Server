/*
 * Bastille.ID Identity Server
 * (c) Copyright Talegen, LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
*/

namespace Bastille.Id.Server.Core.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using Newtonsoft.Json;

    /// <summary>
    /// This class contains extensions for the Stream object.
    /// </summary>
    public static class StreamExtensions
    {
        /// <summary>
        /// This method is used to read and return a string of data from a specified stream.
        /// </summary>
        /// <param name="stream">Contains the stream to read string data from.</param>
        /// <param name="bufferSize">Contains an optional byte buffer read size.</param>
        /// <returns>Returns stream data as a string.</returns>
        public static byte[] ReadAll(this Stream stream, int bufferSize = 4096)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (bufferSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bufferSize));
            }

            using (MemoryStream ms = new MemoryStream((int)stream.Length))
            {
                byte[] buffer = new byte[bufferSize];
                int bytesRead;

                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) != 0)
                {
                    ms.Write(buffer, 0, bytesRead);
                }

                return ms.ToArray();
            }
        }
    }
}