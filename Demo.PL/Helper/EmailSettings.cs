﻿using Demo.DAL.Models;
using System.Net;
using System.Net.Mail;

namespace Demo.PL.Helper
{
	public class EmailSettings
	{
		public static void SendEmail(Email email)
		{
			// Mail server : gmail
			var client = new SmtpClient("smtp.gmail.com", 587);
			client.EnableSsl = true;
			client.Credentials = new NetworkCredential("routec41v02@gmail.com", "bqfivjutajhfxgto");

			client.Send("routec41v02@gmail.com", email.Recipients, email.Subject, email.Body);

		}
	}
}
