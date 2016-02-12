package models

case class EmailMessageId(messageId: String) extends AnyVal {
  def validIdOption = Some(messageId).filterNot(_ == "") // Prevents using invalid empty string when using mock
}