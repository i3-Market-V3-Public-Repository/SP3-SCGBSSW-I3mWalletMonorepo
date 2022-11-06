export const example = {
  dataSharingAgreement: {
    dataOfferingDescription: {
      dataOfferingId: 'string',
      version: 0,
      title: 'Well-being data #14',
      category: 'string',
      active: true
    },
    parties: {
      providerDid: 'did:ethr:i3m:0x02439ce2f97d51e9cb170e3c68a901e524b00f52bc928e851d81e19c2ae7f62c55',
      consumerDid: 'did:ethr:i3m:0x03f53bea256d9183fd224c8d63f31d2b091eda56a9a0317cf9b38a1307c0bafd40'
    },
    purpose: 'string',
    duration: {
      creationDate: 0,
      startDate: 0,
      endDate: 0
    },
    intendedUse: {
      processData: false,
      shareDataWithThirdParty: false,
      editData: false
    },
    licenseGrant: {
      transferable: false,
      exclusiveness: false,
      paidUp: false,
      revocable: false,
      processing: false,
      modifying: false,
      analyzing: false,
      storingData: false,
      storingCopy: false,
      reproducing: false,
      distributing: false,
      loaning: false,
      selling: false,
      renting: false,
      furtherLicensing: false,
      leasing: false
    },
    dataStream: false,
    personalData: false,
    pricingModel: {
      paymentType: 'string',
      pricingModelName: 'string',
      basicPrice: 0,
      currency: 'string',
      fee: 0,
      hasPaymentOnSubscription: {
        paymentOnSubscriptionName: 'string',
        paymentType: 'string',
        timeDuration: 'string',
        description: 'string',
        repeat: 'string',
        hasSubscriptionPrice: 0
      },
      hasFreePrice: {
        hasPriceFree: true
      }
    },
    dataExchangeAgreement: {
      orig: '{"alg":"ES256","crv":"P-256","kty":"EC","x":"gdt9dxd1Q9p5fn8Pch8tuMf6h4lZ_NtbgeVAddPkk5M","y":"coJR5-TGBUwIV_5YovlWzt4suV0wnxfvWJDvekJBCwQ"}',
      dest: '{"alg":"ES256","crv":"P-256","kty":"EC","x":"YI28gvV0utmvjobKned_4m63bc2SkJuKxJBllANfKUc","y":"JMKzTxxe4jNcoZYO4D7Xe_nnZtKeZy5z_JmqjoUyLf8"}',
      encAlg: 'A256GCM',
      signingAlg: 'ES256',
      hashAlg: 'SHA-256',
      ledgerContractAddress: '0x8d407A1722633bDD1dcf221474be7a44C05d7c2F',
      ledgerSignerAddress: '0x17bd12C2134AfC1f6E9302a532eFE30C19B9E903',
      pooToPorDelay: 10000,
      pooToPopDelay: 20000,
      pooToSecretDelay: 180000
    },
    signatures: {
      providerSignature: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJkYXRhT2ZmZXJpbmdEZXNjcmlwdGlvbiI6eyJkYXRhT2ZmZXJpbmdJZCI6InN0cmluZyIsInZlcnNpb24iOjAsInRpdGxlIjoiV2VsbC1iZWluZyBkYXRhICMxNCIsImNhdGVnb3J5Ijoic3RyaW5nIiwiYWN0aXZlIjp0cnVlfSwicGFydGllcyI6eyJwcm92aWRlckRpZCI6ImRpZDpldGhyOmkzbToweDAyNDM5Y2UyZjk3ZDUxZTljYjE3MGUzYzY4YTkwMWU1MjRiMDBmNTJiYzkyOGU4NTFkODFlMTljMmFlN2Y2MmM1NSIsImNvbnN1bWVyRGlkIjoiZGlkOmV0aHI6aTNtOjB4MDNmNTNiZWEyNTZkOTE4M2ZkMjI0YzhkNjNmMzFkMmIwOTFlZGE1NmE5YTAzMTdjZjliMzhhMTMwN2MwYmFmZDQwIn0sInB1cnBvc2UiOiJzdHJpbmciLCJkdXJhdGlvbiI6eyJjcmVhdGlvbkRhdGUiOjAsInN0YXJ0RGF0ZSI6MCwiZW5kRGF0ZSI6MH0sImludGVuZGVkVXNlIjp7InByb2Nlc3NEYXRhIjpmYWxzZSwic2hhcmVEYXRhV2l0aFRoaXJkUGFydHkiOmZhbHNlLCJlZGl0RGF0YSI6ZmFsc2V9LCJsaWNlbnNlR3JhbnQiOnsidHJhbnNmZXJhYmxlIjpmYWxzZSwiZXhjbHVzaXZlbmVzcyI6ZmFsc2UsInBhaWRVcCI6ZmFsc2UsInJldm9jYWJsZSI6ZmFsc2UsInByb2Nlc3NpbmciOmZhbHNlLCJtb2RpZnlpbmciOmZhbHNlLCJhbmFseXppbmciOmZhbHNlLCJzdG9yaW5nRGF0YSI6ZmFsc2UsInN0b3JpbmdDb3B5IjpmYWxzZSwicmVwcm9kdWNpbmciOmZhbHNlLCJkaXN0cmlidXRpbmciOmZhbHNlLCJsb2FuaW5nIjpmYWxzZSwic2VsbGluZyI6ZmFsc2UsInJlbnRpbmciOmZhbHNlLCJmdXJ0aGVyTGljZW5zaW5nIjpmYWxzZSwibGVhc2luZyI6ZmFsc2V9LCJkYXRhU3RyZWFtIjpmYWxzZSwicGVyc29uYWxEYXRhIjpmYWxzZSwicHJpY2luZ01vZGVsIjp7InBheW1lbnRUeXBlIjoic3RyaW5nIiwicHJpY2luZ01vZGVsTmFtZSI6InN0cmluZyIsImJhc2ljUHJpY2UiOjAsImN1cnJlbmN5Ijoic3RyaW5nIiwiZmVlIjowLCJoYXNQYXltZW50T25TdWJzY3JpcHRpb24iOnsicGF5bWVudE9uU3Vic2NyaXB0aW9uTmFtZSI6InN0cmluZyIsInBheW1lbnRUeXBlIjoic3RyaW5nIiwidGltZUR1cmF0aW9uIjoic3RyaW5nIiwiZGVzY3JpcHRpb24iOiJzdHJpbmciLCJyZXBlYXQiOiJzdHJpbmciLCJoYXNTdWJzY3JpcHRpb25QcmljZSI6MH0sImhhc0ZyZWVQcmljZSI6eyJoYXNQcmljZUZyZWUiOnRydWV9fSwiZGF0YUV4Y2hhbmdlQWdyZWVtZW50Ijp7Im9yaWciOiJ7XCJhbGdcIjpcIkVTMjU2XCIsXCJjcnZcIjpcIlAtMjU2XCIsXCJrdHlcIjpcIkVDXCIsXCJ4XCI6XCJnZHQ5ZHhkMVE5cDVmbjhQY2g4dHVNZjZoNGxaX050YmdlVkFkZFBrazVNXCIsXCJ5XCI6XCJjb0pSNS1UR0JVd0lWXzVZb3ZsV3p0NHN1VjB3bnhmdldKRHZla0pCQ3dRXCJ9IiwiZGVzdCI6IntcImFsZ1wiOlwiRVMyNTZcIixcImNydlwiOlwiUC0yNTZcIixcImt0eVwiOlwiRUNcIixcInhcIjpcIllJMjhndlYwdXRtdmpvYktuZWRfNG02M2JjMlNrSnVLeEpCbGxBTmZLVWNcIixcInlcIjpcIkpNS3pUeHhlNGpOY29aWU80RDdYZV9ublp0S2VaeTV6X0ptcWpvVXlMZjhcIn0iLCJlbmNBbGciOiJBMjU2R0NNIiwic2lnbmluZ0FsZyI6IkVTMjU2IiwiaGFzaEFsZyI6IlNIQS0yNTYiLCJsZWRnZXJDb250cmFjdEFkZHJlc3MiOiIweDhkNDA3QTE3MjI2MzNiREQxZGNmMjIxNDc0YmU3YTQ0QzA1ZDdjMkYiLCJsZWRnZXJTaWduZXJBZGRyZXNzIjoiMHgxN2JkMTJDMjEzNEFmQzFmNkU5MzAyYTUzMmVGRTMwQzE5QjlFOTAzIiwicG9vVG9Qb3JEZWxheSI6MTAwMDAsInBvb1RvUG9wRGVsYXkiOjIwMDAwLCJwb29Ub1NlY3JldERlbGF5IjoxODAwMDB9LCJpc3MiOiJkaWQ6ZXRocjppM206MHgwMjQzOWNlMmY5N2Q1MWU5Y2IxNzBlM2M2OGE5MDFlNTI0YjAwZjUyYmM5MjhlODUxZDgxZTE5YzJhZTdmNjJjNTUiLCJpYXQiOjE2Njc2ODcwNTd9.gPz-bSxBqkuIwqOxYxe8-7dEzYSmOiSmzcxbTgISNO1bEut3PBEPA92ZK73LgJDaaP6j3726fverqNDUDcCXWQ',
      consumerSignature: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJkYXRhT2ZmZXJpbmdEZXNjcmlwdGlvbiI6eyJkYXRhT2ZmZXJpbmdJZCI6InN0cmluZyIsInZlcnNpb24iOjAsInRpdGxlIjoiV2VsbC1iZWluZyBkYXRhICMxNCIsImNhdGVnb3J5Ijoic3RyaW5nIiwiYWN0aXZlIjp0cnVlfSwicGFydGllcyI6eyJwcm92aWRlckRpZCI6ImRpZDpldGhyOmkzbToweDAyNDM5Y2UyZjk3ZDUxZTljYjE3MGUzYzY4YTkwMWU1MjRiMDBmNTJiYzkyOGU4NTFkODFlMTljMmFlN2Y2MmM1NSIsImNvbnN1bWVyRGlkIjoiZGlkOmV0aHI6aTNtOjB4MDNmNTNiZWEyNTZkOTE4M2ZkMjI0YzhkNjNmMzFkMmIwOTFlZGE1NmE5YTAzMTdjZjliMzhhMTMwN2MwYmFmZDQwIn0sInB1cnBvc2UiOiJzdHJpbmciLCJkdXJhdGlvbiI6eyJjcmVhdGlvbkRhdGUiOjAsInN0YXJ0RGF0ZSI6MCwiZW5kRGF0ZSI6MH0sImludGVuZGVkVXNlIjp7InByb2Nlc3NEYXRhIjpmYWxzZSwic2hhcmVEYXRhV2l0aFRoaXJkUGFydHkiOmZhbHNlLCJlZGl0RGF0YSI6ZmFsc2V9LCJsaWNlbnNlR3JhbnQiOnsidHJhbnNmZXJhYmxlIjpmYWxzZSwiZXhjbHVzaXZlbmVzcyI6ZmFsc2UsInBhaWRVcCI6ZmFsc2UsInJldm9jYWJsZSI6ZmFsc2UsInByb2Nlc3NpbmciOmZhbHNlLCJtb2RpZnlpbmciOmZhbHNlLCJhbmFseXppbmciOmZhbHNlLCJzdG9yaW5nRGF0YSI6ZmFsc2UsInN0b3JpbmdDb3B5IjpmYWxzZSwicmVwcm9kdWNpbmciOmZhbHNlLCJkaXN0cmlidXRpbmciOmZhbHNlLCJsb2FuaW5nIjpmYWxzZSwic2VsbGluZyI6ZmFsc2UsInJlbnRpbmciOmZhbHNlLCJmdXJ0aGVyTGljZW5zaW5nIjpmYWxzZSwibGVhc2luZyI6ZmFsc2V9LCJkYXRhU3RyZWFtIjpmYWxzZSwicGVyc29uYWxEYXRhIjpmYWxzZSwicHJpY2luZ01vZGVsIjp7InBheW1lbnRUeXBlIjoic3RyaW5nIiwicHJpY2luZ01vZGVsTmFtZSI6InN0cmluZyIsImJhc2ljUHJpY2UiOjAsImN1cnJlbmN5Ijoic3RyaW5nIiwiZmVlIjowLCJoYXNQYXltZW50T25TdWJzY3JpcHRpb24iOnsicGF5bWVudE9uU3Vic2NyaXB0aW9uTmFtZSI6InN0cmluZyIsInBheW1lbnRUeXBlIjoic3RyaW5nIiwidGltZUR1cmF0aW9uIjoic3RyaW5nIiwiZGVzY3JpcHRpb24iOiJzdHJpbmciLCJyZXBlYXQiOiJzdHJpbmciLCJoYXNTdWJzY3JpcHRpb25QcmljZSI6MH0sImhhc0ZyZWVQcmljZSI6eyJoYXNQcmljZUZyZWUiOnRydWV9fSwiZGF0YUV4Y2hhbmdlQWdyZWVtZW50Ijp7Im9yaWciOiJ7XCJhbGdcIjpcIkVTMjU2XCIsXCJjcnZcIjpcIlAtMjU2XCIsXCJrdHlcIjpcIkVDXCIsXCJ4XCI6XCJnZHQ5ZHhkMVE5cDVmbjhQY2g4dHVNZjZoNGxaX050YmdlVkFkZFBrazVNXCIsXCJ5XCI6XCJjb0pSNS1UR0JVd0lWXzVZb3ZsV3p0NHN1VjB3bnhmdldKRHZla0pCQ3dRXCJ9IiwiZGVzdCI6IntcImFsZ1wiOlwiRVMyNTZcIixcImNydlwiOlwiUC0yNTZcIixcImt0eVwiOlwiRUNcIixcInhcIjpcIllJMjhndlYwdXRtdmpvYktuZWRfNG02M2JjMlNrSnVLeEpCbGxBTmZLVWNcIixcInlcIjpcIkpNS3pUeHhlNGpOY29aWU80RDdYZV9ublp0S2VaeTV6X0ptcWpvVXlMZjhcIn0iLCJlbmNBbGciOiJBMjU2R0NNIiwic2lnbmluZ0FsZyI6IkVTMjU2IiwiaGFzaEFsZyI6IlNIQS0yNTYiLCJsZWRnZXJDb250cmFjdEFkZHJlc3MiOiIweDhkNDA3QTE3MjI2MzNiREQxZGNmMjIxNDc0YmU3YTQ0QzA1ZDdjMkYiLCJsZWRnZXJTaWduZXJBZGRyZXNzIjoiMHgxN2JkMTJDMjEzNEFmQzFmNkU5MzAyYTUzMmVGRTMwQzE5QjlFOTAzIiwicG9vVG9Qb3JEZWxheSI6MTAwMDAsInBvb1RvUG9wRGVsYXkiOjIwMDAwLCJwb29Ub1NlY3JldERlbGF5IjoxODAwMDB9LCJpc3MiOiJkaWQ6ZXRocjppM206MHgwM2Y1M2JlYTI1NmQ5MTgzZmQyMjRjOGQ2M2YzMWQyYjA5MWVkYTU2YTlhMDMxN2NmOWIzOGExMzA3YzBiYWZkNDAiLCJpYXQiOjE2Njc2ODcwNTd9.MWqocSiKRW_hGeTnHlNC4MrRFIntnWYelqQYlJrEIcssWVJ_cEeVD5qUMiJy2dAjGHoSXhWkEvbUIN1udqaOXg'
    }
  },
  providerJwks: {
    publicJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: 'gdt9dxd1Q9p5fn8Pch8tuMf6h4lZ_NtbgeVAddPkk5M',
      y: 'coJR5-TGBUwIV_5YovlWzt4suV0wnxfvWJDvekJBCwQ',
      alg: 'ES256'
    },
    privateJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: 'gdt9dxd1Q9p5fn8Pch8tuMf6h4lZ_NtbgeVAddPkk5M',
      y: 'coJR5-TGBUwIV_5YovlWzt4suV0wnxfvWJDvekJBCwQ',
      d: 'KeFLl9SKwpJHuAmyyxe7YXiCr4cDGK4uMU1fxnrrLjw',
      alg: 'ES256'
    }
  },
  consumerJwks: {
    publicJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: 'YI28gvV0utmvjobKned_4m63bc2SkJuKxJBllANfKUc',
      y: 'JMKzTxxe4jNcoZYO4D7Xe_nnZtKeZy5z_JmqjoUyLf8',
      alg: 'ES256'
    },
    privateJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: 'YI28gvV0utmvjobKned_4m63bc2SkJuKxJBllANfKUc',
      y: 'JMKzTxxe4jNcoZYO4D7Xe_nnZtKeZy5z_JmqjoUyLf8',
      d: 'KckaDbkuLIH1rbOSxEvfWgNFBcOYDsShvlzSb8N4ijI',
      alg: 'ES256'
    }
  }
}
