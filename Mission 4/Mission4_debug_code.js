  async function parseFile() {
    const fileInput = document.getElementById("fileInput");
    const file = fileInput.files[0];
    if (!file) {
      alert("Please select a file");
      return;
    }

    const arrayBuffer = await file.arrayBuffer();
    const dataView = new DataView(arrayBuffer);

    const signature = getString(dataView, 0, 5);
    if (signature !== "AGPAY") {
      alert("Invalid Card");
      return;
    }
    const version = getString(dataView, 5, 2);
    const encryptionKey = new Uint8Array(arrayBuffer.slice(7, 39));
    const reserved = new Uint8Array(arrayBuffer.slice(39, 49));

    const footerSignature = getString(
      dataView,
      arrayBuffer.byteLength - 22,
      6
    );
    if (footerSignature !== "ENDAGP") {
      alert("Invalid Card");
      return;
    }
    const checksum = new Uint8Array(
      arrayBuffer.slice(arrayBuffer.byteLength - 16, arrayBuffer.byteLength)
    );

    const iv = new Uint8Array(arrayBuffer.slice(49, 65));
    const encryptedData = new Uint8Array(
      arrayBuffer.slice(65, arrayBuffer.byteLength - 22)
    );

    const calculatedChecksum = hexToBytes(
      SparkMD5.ArrayBuffer.hash(new Uint8Array([...iv, ...encryptedData]))
    );

    if (!arrayEquals(calculatedChecksum, checksum)) {
      alert("Invalid Card");
      return;
    }

    const decryptedData = await decryptData(
      encryptedData,
      encryptionKey,
      iv
    );

    console.log(decryptedData)

    const cardNumber = getString(decryptedData, 0, 16);
    const cardExpiryDate = decryptedData.getUint32(20, false);
    const balance = decryptedData.getBigUint64(24, false);

    console.log(balance)

    document.getElementById("cardNumber").textContent =
      formatCardNumber(cardNumber);
    document.getElementById("cardExpiryDate").textContent =
      "VALID THRU " + formatDate(new Date(cardExpiryDate * 1000));
    document.getElementById("balance").textContent =
      "$" + balance.toString();
    console.log(balance);
    if (balance == 313371337) {
      function arrayBufferToBase64(buffer) {
        let binary = "";
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
      }

      const base64CardData = arrayBufferToBase64(arrayBuffer);

      const formData = new FormData();
      formData.append("data", base64CardData);

      try {
        const response = await fetch("submit", {
          method: "POST",
          body: formData,
        });

        const result = await response.json();
        if (result.success) {
          alert(result.success);
        } else {
          alert("Invalid Card");
        }
      } catch (error) {
        alert("Invalid Card");
      }
    }
  }

  function getString(dataView, offset, length) {
    let result = "";
    for (let i = offset; i < offset + length; i++) {
      result += String.fromCharCode(dataView.getUint8(i));
    }
    return result;
  }

  function arrayEquals(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  function hexToBytes(hex) {
    const bytes = [];
    for (let c = 0; c < hex.length; c += 2) {
      bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return new Uint8Array(bytes);
  }

  async function decryptData(encryptedData, key, iv) {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-CBC" },
      false,
      ["decrypt"]
    );
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: iv },
      cryptoKey,
      encryptedData
    );
    return new DataView(decryptedBuffer);
  }

  function formatCardNumber(cardNumber) {
    return cardNumber.replace(/(.{4})/g, "$1 ").trim();
  }

  function formatDate(date) {
    const month = (date.getMonth() + 1).toString().padStart(2, "0");
    const year = date.getFullYear().toString().slice(2);
    return `${month}/${year}`;
  }
